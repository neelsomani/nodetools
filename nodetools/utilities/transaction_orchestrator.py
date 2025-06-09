"""
Orchestrates the processing of both historical and real-time XRPL transactions,
ensuring proper sequencing and consistency of transaction processing.
"""
# Standard imports
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from decimal import Decimal
import asyncio
import traceback
import time
from datetime import datetime, timedelta, timezone

# Third party imports
from loguru import logger
from xrpl.models import Response
from cryptography.fernet import InvalidToken

# Nodetools imports
from nodetools.models.models import (
    ResponseRule, 
    InteractionType, 
    InteractionPattern, 
    ResponseGenerator, 
    ResponseParameters,
    Dependencies,
    StructuralPattern,
    MemoGroup,
    BusinessLogicProvider
)
from nodetools.models.memo_processor import MemoProcessor
from nodetools.performance.monitor import PerformanceMonitor
from nodetools.protocols.generic_pft_utilities import GenericPFTUtilities
from nodetools.protocols.transaction_repository import TransactionRepository
from nodetools.protocols.credentials import CredentialManager
from nodetools.protocols.openrouter import OpenRouterTool
from nodetools.protocols.encryption import MessageEncryption
from nodetools.protocols.xrpl_monitor import XRPLWebSocketMonitor
from nodetools.protocols.db_manager import DBConnectionManager
from nodetools.utilities.compression import CompressionError
from nodetools.configuration.configuration import NodeConfig, NetworkConfig
from nodetools.configuration.constants import VERIFY_STATE_INTERVAL

def format_duration(seconds: float) -> str:
    """Format a duration in H:m:s format"""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

@dataclass
class ReviewingResult:
    """Represents the outcome of reviewing a single transaction"""
    tx: Dict[str, Any]
    processed: bool
    rule_name: str
    response_tx_hash: Optional[str] = None
    notes: Optional[str] = None
    needs_rereview: bool = False

class TransactionReviewer:
    """
    Handles the core logic of reviewing individual transactions against business rules.
    
    Key responsibilities:
    1. Transaction Pattern Matching:
       - Identifies if transactions match known patterns
       - Routes to appropriate review method based on structural pattern
    
    2. Group Management:
       - Maintains state of pending transaction groups
       - Handles chunked message reassembly
       - Manages group lifecycle and cleanup
    
    3. Memo Processing:
       - Coordinates memo processing through MemoProcessor
       - Provides encryption context (credentials, keys) for memo decryption
       - Creates synthetic transactions with processed memo content
    
    4. Business Rule Application:
       - Validates transactions against business rules
       - Determines if responses are needed
       - Finds and validates response transactions
    
    Dependencies:
    - business_logic: Provides transaction patterns and rules
    - repository: For querying transaction history
    - credential_manager: For decryption operations
    - message_encryption: For ECDH handshake operations
    - node_config: For system address configuration
    
    State Management:
    - Tracks pending transaction groups
    - Manages sync mode state
    - Handles cleanup of stale groups
    """
    def __init__(
            self,
            business_logic: BusinessLogicProvider,
            dependencies: Dependencies,
            notification_queue: Optional[asyncio.Queue] = None
        ):
        # business logic dependencies
        self.graph = business_logic.transaction_graph
        self.pattern_rule_map = business_logic.pattern_rule_map
        self.notification_queue = notification_queue

        # framework dependencies
        self.dependencies = dependencies

        # state
        self.pending_groups: Dict[str, MemoGroup] = {}  # group_id -> MemoGroup
        self.STALE_GROUP_TIMEOUT = timedelta(minutes=10)
        self.latest_processed_time: Optional[datetime] = None
        self.is_syncing: bool = True  # Flag to indicate if we're in sync mode

    def end_sync_mode(self):
        self.is_syncing = False
        self._cleanup_stale_groups()
    
    def _cleanup_stale_groups(self):
        """Remove groups that haven't received new chunks within threshold"""
        # Skip cleanup during sync mode
        if self.is_syncing:
            return

        # Update latest processed time
        current_time = datetime.now(timezone.utc)
        if not self.latest_processed_time or current_time > self.latest_processed_time:
            self.latest_processed_time = current_time

        for group_id, group in list(self.pending_groups.items()):
            # Get timestamp of last transaction in group
            last_tx_time = max(
                tx['datetime'].replace(tzinfo=timezone.utc) if tx['datetime'].tzinfo is None else tx['datetime']
                for tx in group.memos
            )
            
            if last_tx_time + self.STALE_GROUP_TIMEOUT < current_time:
                self.pending_groups.pop(group_id)

    async def review_transaction(self, tx: Dict[str, Any]) -> ReviewingResult:
        """Review a single transaction against all rules"""

        # First determine if transaction needs grouping
        structural_result = StructuralPattern.match(tx)

        match structural_result:
            case StructuralPattern.NO_MEMO:
                return ReviewingResult(
                    tx=tx,
                    processed=True,
                    rule_name="NoRule",
                    notes="No memo present"
                )
            case StructuralPattern.DIRECT_MATCH:
                return await self._review_direct_match(tx)
            
            case StructuralPattern.NEEDS_GROUPING:
                return await self._review_group(tx, is_standardized=True)
            
            case StructuralPattern.NEEDS_LEGACY_GROUPING:
                return await self._review_group(tx, is_standardized=False)
            
    async def _review_group(self, tx: Dict[str, Any], is_standardized: bool) -> ReviewingResult:
        """Handle review of grouped transactions"""
        group_id = tx.get('memo_type')

        # Clean up stale groups
        self._cleanup_stale_groups()

        # Get or create group
        if group_id not in self.pending_groups:
            self.pending_groups[group_id] = MemoGroup.create_from_transaction(tx)
        else:
            if not self.pending_groups[group_id].add_memo(tx):
                logger.warning(f"Failed to add message to group {group_id}")
                return ReviewingResult(
                    tx=tx,
                    processed=True,
                    rule_name="NoRule",
                    notes=f"Message doesn't belong to group {group_id}"
                )
            
        group = self.pending_groups[group_id]
        structure = group.structure

        # For standardized format, only attempting processing when we have all chunks
        if is_standardized and len(group.chunk_indices) < structure.total_chunks:
            return ReviewingResult(
                tx=tx,
                processed=False,
                rule_name="NoRule",
                notes=f"Waiting for more chunks ({len(group.chunk_indices)}/{structure.total_chunks})"
            )
        
        # Try processing the group
        try:
            processed_content = await MemoProcessor.process_group(
                group,
                credential_manager=self.dependencies.credential_manager,
                message_encryption=self.dependencies.message_encryption,
                node_config=self.dependencies.node_config
            )
            
            # Create synthetic transaction with processed content
            complete_tx = tx.copy()
            complete_tx['memo_data'] = processed_content
            self.pending_groups.pop(group_id)
            return await self._review_direct_match(complete_tx)
        
        except (CompressionError, InvalidToken) as e:
            # For legacy groups, we lack the metadata to explicitly know if we've received all chunks
            # So we'll keep the group in pending and try again later if we receive more chunks
            # Groups in pending are subject to a timeout and will be cleaned up if they're not updated
            if not is_standardized:
                return ReviewingResult(
                    tx=tx,
                    processed=True,
                    rule_name="NoRule",
                    notes=f"Failed to process group (legacy). May be due to missing chunks."
                )
            
            # For standardized format, re-raise to be caught by general exception handler
            raise
        
        except Exception as e:
            logger.error(f"Error processing group {group_id}: {e}")
            logger.error(traceback.format_exc())

            # Remove the failed group
            self.pending_groups.pop(group_id)
            return ReviewingResult(
                tx=tx,
                processed=True,
                rule_name="ProcessingError",
                notes=f"Failed to process group: {str(e)}"
            )

    async def _review_direct_match(self, tx: Dict[str, Any]) -> ReviewingResult:
        """Handle review of transactions that can be matched directly"""
        # First find matching pattern
        pattern_id = self.graph.find_matching_pattern(tx)

        if not pattern_id:
            return ReviewingResult(
                tx=tx,
                processed=True,  # We've reviewed it and found no matching pattern
                rule_name="NoRule",
                notes="No matching pattern found"
            )
        
        pattern = self.graph.patterns[pattern_id]

        # Get the corresponding rule for this pattern
        rule = self.pattern_rule_map[pattern_id]
        if not rule:
            logger.error(f"No rule found for pattern_id: {pattern_id}")
            return ReviewingResult(
                tx=tx,
                processed=True,
                rule_name="NoRule",
                notes=f"No rule found for pattern {pattern_id}"
            )

        try:

            if await rule.validate(tx, dependencies=self.dependencies):  # Pure business rule validation

                # Process based on the pattern's transaction type
                match pattern.transaction_type:
                    # Response or standalone transactions don't need responses
                    case InteractionType.RESPONSE | InteractionType.STANDALONE:

                        # These transactions don't need processing but might need notification, but only if they're recent.
                        # Normalize the datetime to UTC to check if it's recent
                        tx_datetime = tx['datetime']
                        if isinstance(tx_datetime, datetime) and tx_datetime.tzinfo is None:
                            tx_datetime = tx_datetime.replace(tzinfo=timezone.utc)

                        if pattern.notify and self.notification_queue and tx_datetime > (datetime.now(timezone.utc) - timedelta(minutes=1)):
                            await self.notification_queue.put(tx)
                            logger.debug(f"TransactionReviewer: Queued notification for transaction {tx['hash']}")

                        return ReviewingResult(
                            tx=tx,
                            processed=True, 
                            rule_name=rule.__class__.__name__,
                            notes=f"Processed {pattern.transaction_type.value} transaction"
                        )
                    
                    # Request transactions need responses
                    case InteractionType.REQUEST:
                        # 4. Get response query and execute it
                        response_query = await rule.find_response(tx)
                        result = await self.dependencies.transaction_repository.execute_query(
                            response_query.query,
                            response_query.params
                        )
                        # Assumes that no response found will return None (execute_query returns None)
                        # So we need enforce_column_structure=False arg in execute_query to allow for None results
                        response_tx = result[0] if result else None

                        if not response_tx:
                            # Request needs processing and might need notification
                            if pattern.notify and self.notification_queue:
                                await self.notification_queue.put(tx)
                                logger.debug(f"TransactionReviewer: Queued notification for transaction {tx['hash']}")

                            return ReviewingResult(
                                tx=tx,
                                processed=False,  # We've reviewed it and found no response
                                rule_name=rule.__class__.__name__,
                                notes="Required response not found",
                                needs_rereview=True
                            )

                        # 5. Response found
                        return ReviewingResult(
                            tx=tx,
                            processed=True,  # We've reviewed it and found the required response
                            rule_name=rule.__class__.__name__,
                            response_tx_hash=response_tx.get("hash"),
                            notes="Response found"
                        )
                    
            else:
                # Rule validation failed
                return ReviewingResult(
                    tx=tx,
                    processed=True,  # We've reviewed it and determined it failed validation
                    rule_name=rule.__class__.__name__,
                    notes=f"Failed validation for rule {rule.__class__.__name__}"
                )

        except Exception as e:
            logger.error(f"Error processing rule {rule.__class__.__name__}: {e}")
            logger.error(traceback.format_exc())
            logger.error(f"Transaction: {tx}")
    
@dataclass
class ResponseRoutingResult:
    """Represents the result of determining the appropriate response pattern for a transaction"""
    success: bool
    pattern_id: str
    notes: Optional[str] = None

@dataclass
class QueueConfig:
    """Configuration for a response queue and its generator"""
    queue: asyncio.Queue
    pattern: InteractionPattern
    rule: ResponseRule

class ResponseQueueRouter:
    """
    Manages the routing of transactions that need responses to appropriate processing queues.
    Also tracks pending responses and triggers re-review when responses are confirmed.
    """
    def __init__(
            self, 
            business_logic: BusinessLogicProvider, 
            review_queue: asyncio.Queue,
            transaction_repository: TransactionRepository,
            shutdown_event: asyncio.Event
        ):
        self.graph = business_logic.transaction_graph
        self.pattern_rule_map = business_logic.pattern_rule_map
        self.review_queue = review_queue
        self.transaction_repository = transaction_repository
        self._shutdown_event = shutdown_event

        # Track pending responses and their review queues
        self.pending_responses: Dict[str, Dict[str, Any]] = {}  # tx_hash -> original_tx
        self.pending_rereviews: Dict[str, Dict[str, Any]] = {}
        self.MAX_RETRY_COUNT = 10
        self.RETRY_DELAY = 5  # seconds

        # Initialize queue configurations
        self.queue_configs: Dict[str, QueueConfig] = self._initialize_queue_configs()
        self.processing_counts: Dict[str, int] = {
            pattern_id: 0 for pattern_id in self.queue_configs.keys()
        }

    def _initialize_queue_configs(self) -> Dict[str, asyncio.Queue]:
        """Initialize queue configurations based on response patterns in business rules"""
        configs: Dict[str, QueueConfig] = {}

        # Create a queue for each RESPONSE type pattern in the graph
        for pattern_id, pattern in self.graph.patterns.items():
            if pattern.transaction_type == InteractionType.RESPONSE:
                rule = self.pattern_rule_map[pattern_id]
                if isinstance(rule, ResponseRule):
                    configs[pattern_id] = QueueConfig(
                        queue=asyncio.Queue(),
                        pattern=pattern,
                        rule=rule
                    )
                    logger.debug(f"ResponseQueueRouter: Adding queue config for pattern '{pattern_id}'")
    
        return configs
    
    def get_queue_config(self, pattern_id: str) -> Optional[QueueConfig]:
        """Get the queue configuration for a given pattern ID"""
        return self.queue_configs.get(pattern_id)
    
    def get_all_queue_configs(self) -> Dict[str, QueueConfig]:
        """Get all queue configurations"""
        return self.queue_configs
    
    async def route_transaction(self, tx: Dict[str, Any]) -> bool:
        """Route transaction to appropriate response queue based on its matching rule"""
        try:

            # DEBUGGING
            logger.debug(f"Routing transaction {tx['hash']}")
            logger.debug(f"Transaction memo_type: {tx.get('memo_type')}")
            logger.debug(f"Transaction memo_format: {tx.get('memo_format')}")
            logger.debug(f"Transaction memo_data: {tx.get('memo_data')}")

            result = await self._determine_response_pattern(tx)

            logger.debug(f"Routing result: {result}")

            if result.success:
                # Store original transaction before routing
                self.pending_responses[tx['hash']] = tx

                # Route transaction to appropriate response queue
                await self.queue_configs[result.pattern_id].queue.put(tx)
                logger.debug(f"Routed transaction {tx['hash']} to {result.pattern_id} queue")
                return True
            return False

        except Exception as e:
            logger.error(f"Error routing transaction {tx['hash']}: {e}")
            logger.error(traceback.format_exc())
            return False
        
    async def _determine_response_pattern(self, tx: Dict[str, Any]) -> ResponseRoutingResult:
        """
        Determines which response queue a transaction should be routed to.
        
        Flow:
        1. Find the request pattern that matches this transaction
        2. Get its first valid response pattern
        3. Convert that response pattern to a pattern ID for queue routing
        
        Returns:
            ResponseRoutingResult with:
            - success: Whether a valid response queue was found
            - pattern_id: The pattern ID of the response queue to use
            - notes: Additional context about the routing decision
        """
        # First find matching pattern in graph
        request_pattern_id = self.graph.find_matching_pattern(tx)
        if not request_pattern_id:
            return ResponseRoutingResult(
                success=False,
                pattern_id="unknown",
                notes="No matching request pattern found"
            )
        
        request_pattern = self.graph.patterns[request_pattern_id]
        
        # Verify it's a request type pattern
        if request_pattern.transaction_type != InteractionType.REQUEST:
            return ResponseRoutingResult(
                success=False,
                pattern_id="unknown",
                notes=f"Pattern {request_pattern_id} is not a request type"
            )
    
        # Get the first valid response pattern
        response_pattern = next(iter(request_pattern.valid_responses))
        response_pattern_id = self.graph.get_pattern_id_by_memo_pattern(response_pattern)

        if not response_pattern_id:
            return ResponseRoutingResult(
                success=False,
                pattern_id="unknown",
                notes="Could not find response pattern ID"
            )

        return ResponseRoutingResult(
            success=True,
            pattern_id=response_pattern_id,
            notes=f"Transaction will be routed to {response_pattern_id} queue"
        )
    
    async def confirm_response_sent(self, request_tx_hash: str):
        """Queue transaction for re-review with retry mechanism"""
        if request_tx_hash in self.pending_responses:
            original_tx = self.pending_responses.pop(request_tx_hash)
            
            # Add to pending re-reviews with retry count
            self.pending_rereviews[request_tx_hash] = {
                'tx': original_tx,
                'retries': 0,
                'next_retry': time.time() + self.RETRY_DELAY
            }
            logger.debug(f"Queued {request_tx_hash} for re-review with retries")
    
    async def retry_pending_reviews(self):
        """Background task to retry pending re-reviews"""
        while not self._shutdown_event.is_set():
            try:
                current_time = time.time()
                
                # Get all transactions that need retry
                for tx_hash, info in list(self.pending_rereviews.items()):
                    if current_time >= info['next_retry']:
                        try:
                            # Check if specific transaction exists in decoded_memos view
                            tx = await self.transaction_repository.get_decoded_memo_w_processing(tx_hash)
                            logger.debug(f"ResponseQueueRouter: Checking for processed transaction {tx_hash} in database")
                            
                            if tx:
                                # Found in database with decoded memos, queue for review
                                await self.review_queue.put(tx)  # Use the complete decoded transaction
                                logger.debug(f"Re-queued transaction {tx_hash} for review after {info['retries']} retries")
                                self.pending_rereviews.pop(tx_hash)
                            else:
                                # Not found, increment retry count
                                info['retries'] += 1
                                if info['retries'] >= self.MAX_RETRY_COUNT:
                                    logger.warning(f"Max retries reached for {tx_hash}, giving up")
                                    self.pending_rereviews.pop(tx_hash)
                                else:
                                    # Schedule next retry with exponential backoff
                                    info['next_retry'] = current_time + (self.RETRY_DELAY * (2 ** info['retries']))
                                    logger.debug(f"Scheduling retry {info['retries']} for {tx_hash}")
                        
                        except Exception as e:
                            logger.error(f"Error during retry for {tx_hash}: {e}")
                            logger.error(traceback.format_exc())
                
                # Sleep briefly to prevent busy-waiting
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Error in retry loop: {e}")
                logger.error(traceback.format_exc())
                await asyncio.sleep(5.0)  # Longer sleep on error

class ResponseProcessor:
    """Queue consumer that generates and submits responses to transactions.
    
    Handles the core consume-evaluate-respond loop while delegating the actual
    response generation to a ResponseGenerator provided by the rule.
    """
    def __init__(
            self,
            queue: asyncio.Queue,
            response_manager: ResponseQueueRouter,
            generator: ResponseGenerator,
            dependencies: Dependencies,
            shutdown_event: asyncio.Event,
            pattern_id: str
        ):
        self.queue = queue
        self.response_manager = response_manager
        self.generator = generator
        self.dependencies = dependencies
        self._shutdown_event = shutdown_event
        self.pattern_id = pattern_id
        self.processed_count = 0
        self.fail_count = 0
        self.last_log_time = time.time()
        self.last_activity_time = time.time()
        self.IDLE_LOG_INTERVAL = 3600  # Log idle status every 60 minutes
        self.COUNT_LOG_INTERVAL = 10  # Log count every 10 transactions

    async def run(self):
        """Process transactions from the queue until shutdown"""
        while not self._shutdown_event.is_set():
            try:
                # Get transaction from queue
                tx = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                logger.debug(f"ResponseProcessor_{self.pattern_id}: Got transaction {tx['hash']} from queue")

                # Process the transaction
                response = await self._process_transaction(tx)

                success = self.dependencies.generic_pft_utilities.verify_transaction_response(response)

                if not success:
                    self.fail_count += 1
                    raise Exception(f"ResponseProcessor_{self.pattern_id}: Failed to verify response for transaction {tx['hash']}")

                if success:
                    self.processed_count += 1
                    self.last_activity_time = time.time()
                    self.last_idle_log_time = None  # Reset idle logging on activity
                    logger.debug(f"ResponseProcessor_{self.pattern_id}: Confirming response sent for transaction {tx['hash']}")
                    await self.response_manager.confirm_response_sent(tx['hash'])

                # Log progress by count
                queue_size = self.queue.qsize()
                if queue_size == 0:
                    logger.info(
                        f"ResponseProcessor_{self.pattern_id}: "
                        f"Queue empty. Total processed: {self.processed_count} "
                        f"Total transactions failed: {self.fail_count}"
                    )
                elif self.processed_count % self.COUNT_LOG_INTERVAL == 0:
                    logger.debug(
                        f"ResponseProcessor_{self.pattern_id}: "
                        f"Progress: {self.processed_count} transactions processed. "
                        f"Current queue size: {queue_size}"
                        f"Transactions failed: {self.fail_count}"
                    )

                self.queue.task_done()

            except asyncio.TimeoutError:
                # Log idle status if interval elapsed
                current_time = time.time()
                idle_duration = current_time - self.last_activity_time

                # Only log if we've been idle longer than IDLE_LOG_INTERVAL
                # and haven't logged in the last IDLE_LOG_INTERVAL
                if (idle_duration > self.IDLE_LOG_INTERVAL and 
                    (self.last_idle_log_time is None or 
                     current_time - self.last_idle_log_time > self.IDLE_LOG_INTERVAL)):
                    logger.info(
                        f"Consumer_{self.pattern_id}: "
                        f"Idle for {format_duration(idle_duration)}. "
                        f"Total processed: {self.processed_count} "
                        f"Total transactions failed: {self.fail_count}"
                    )
                    self.last_idle_log_time = current_time  # Reset to avoid spam
                continue

            except Exception as e:
                logger.error(f"BaseConsumer.run: Error processing transaction: {e}")
                logger.error(traceback.format_exc())

    async def _process_transaction(self, tx: Dict[str, Any]) -> Response:
        """Process a single transaction using the generator"""
        try:
            # Evaluate the request
            logger.debug(f"ResponseProcessor_{self.pattern_id}: Evaluating request")
            evaluation = await self.generator.evaluate_request(tx)

            # Construct response parameters
            logger.debug(f"ResponseProcessor_{self.pattern_id}: Constructing response")
            response_params: ResponseParameters = await self.generator.construct_response(tx, evaluation)

            # Get appropriate wallet based on source
            node_wallet = self.dependencies.generic_pft_utilities.spawn_wallet_from_seed(
                self.dependencies.credential_manager.get_credential(f'{response_params.source}__v1xrpsecret')
            )

            # Send response transaction
            logger.debug(f"ResponseProcessor_{self.pattern_id}: Sending response transaction")
            return await self.dependencies.generic_pft_utilities.send_memo(
                wallet_seed_or_wallet=node_wallet,
                memo=response_params.memo,
                destination=response_params.destination,
                pft_amount=response_params.pft_amount
            )

        except Exception as e:
            logger.error(f"ResponseProcessor._process_transaction: Error processing transaction: {e}")
            logger.error(traceback.format_exc())
            return False

    def stop(self):
        """Signal the consumer to stop processing"""
        self._shutdown = True

class ResponseProcessorManager:
    """Manages the lifecycle of async queue consumers"""
    def __init__(
            self, 
            response_manager: ResponseQueueRouter,
            dependencies: Dependencies
        ):
        self.response_manager = response_manager
        self.dependencies = dependencies
        self.consumers: Dict[str, ResponseProcessor] = {}
        self._tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()

    async def start(self):
        """Initialize and start consumers for all response queues"""
        try:
            # Get queue configurations from response manager
            queue_configs = self.response_manager.get_all_queue_configs()

            for pattern_id, config in queue_configs.items():
                # Each rule creates its generator with all necessary dependencies
                generator = config.rule.get_response_generator(self.dependencies)

                # Create consumer
                consumer = ResponseProcessor(
                    queue=config.queue,
                    response_manager=self.response_manager,
                    generator=generator,
                    dependencies=self.dependencies,
                    shutdown_event=self._shutdown_event,
                    pattern_id=pattern_id
                )

                # Store consumer
                self.consumers[pattern_id] = consumer

                # Create and store task
                task = asyncio.create_task(
                    consumer.run(),
                    name=f"ResponseProcessor_{pattern_id}"
                )
                self._tasks.append(task)
                logger.debug(f"ResponseProcessorManager: Started ResponseProcessor for pattern: {pattern_id}")

        except Exception as e:
            logger.error(f"Error starting consumers: {e}")
            logger.error(traceback.format_exc())
            raise

    async def stop(self):
        """Signal all consumers to stop"""
        self._shutdown_event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

@dataclass
class StateSyncStats:
    """Statistics for the state synchronization process"""
    accounts_processed: int = 0
    transactions_found: int = 0
    accounts_with_missing_data: int = 0
    balance_mismatches: int = 0
    balances_corrected: int = 0
    transactions_queued: int = 0
    rows_inserted: int = 0

class TransactionOrchestrator:
    """
    Coordinates the entire transaction processing pipeline, including:
    - Historical data synchronization
    - Real-time transaction monitoring
    - Transaction verification
    - Sequential processing of transactions
    """
    def __init__(
            self,
            dependencies: Dependencies,
            business_logic_provider: BusinessLogicProvider,
            xrpl_monitor: XRPLWebSocketMonitor,
            notifications: bool = False
    ):
        self.business_logic_provider = business_logic_provider
        self.xrpl_monitor = xrpl_monitor
        self.dependencies = dependencies

        # Also maintain direct references to the dependencies
        self.generic_pft_utilities = dependencies.generic_pft_utilities
        self.transaction_repository = dependencies.transaction_repository
        self.credential_manager = dependencies.credential_manager
        self.message_encryption = dependencies.message_encryption
        self.node_config = dependencies.node_config
        self.openrouter = dependencies.openrouter
        self.openai = dependencies.openai

        # Initialize queues and managers
        self.review_queue = asyncio.Queue()     # Queue for transactions needing review
        self.routing_queue = asyncio.Queue()    # Queue for transactions needing responses
        self.reviewer: TransactionReviewer = None  # will be initialized in start()
        self.response_manager: ResponseQueueRouter = None  # will be initialized in start()
        self.consumer_manager: ResponseProcessorManager = None  # will be initialized in start()
        
        # Task management
        self._initial_sync_complete = False
        self._managed_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self.SHUTDOWN_TIMEOUT = 5.0

        # Optional notification queue
        self.notification_queue = asyncio.Queue() if notifications else None

    @property
    def running(self):
        """Check if the transaction orchestrator is running"""
        return bool(self._managed_tasks) and not all(task.done() for task in self._managed_tasks)
    
    def start(self):
        """Start the transaction orchestrator"""
        try:
            # Get or create event loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                return loop.run_until_complete(self._start_async())
            
            return loop.create_task(self._start_async())

        except Exception as e:
            logger.error(f"TransactionOrchestrator: Error starting: {e}")
            logger.error(traceback.format_exc())
            raise

    async def _start_async(self):
        """Start the transaction orchestrator"""
        try:
            # Initialize components
            if not self.reviewer:
                self.reviewer = TransactionReviewer(
                    business_logic=self.business_logic_provider,
                    dependencies=self.dependencies,
                    notification_queue=self.notification_queue
                )
            if not self.response_manager:
                self.response_manager = ResponseQueueRouter(
                    business_logic=self.business_logic_provider,
                    review_queue=self.review_queue,
                    transaction_repository=self.transaction_repository,
                    shutdown_event=self._shutdown_event
                )
            if not self.consumer_manager:
                self.consumer_manager = ResponseProcessorManager(
                    response_manager=self.response_manager,
                    dependencies=self.dependencies
                )

            # Start XRPL monitor
            self.xrpl_monitor.start(queue=self.review_queue)
            if self.xrpl_monitor.monitor_task:
                self._managed_tasks.append(self.xrpl_monitor.monitor_task)

            # Start core processing tasks
            self._managed_tasks.extend([
                asyncio.create_task(self._state_sync_loop(), name="StateSynchronizationLoop"),
                asyncio.create_task(self._review_loop(), name="TransactionReviewLoop"),
                asyncio.create_task(self._route_loop(), name="ResponseRoutingLoop"),
                asyncio.create_task(self._consumer_loop(), name="ConsumerLoop"),
                asyncio.create_task(self.response_manager.retry_pending_reviews(), name="ResponseQueueRouterRetryTask")
            ])

            logger.debug("TransactionOrchestrator: Started all tasks")

        except Exception as e:
            logger.error(f"TransactionOrchestrator: Error starting: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def _get_transaction_batches(self, transactions: List[Dict[str, Any]], batch_size: int):
        """Generate batches of transactions from list."""
        for start in range(0, len(transactions), batch_size):
            yield transactions[start:start + batch_size]

    @PerformanceMonitor.measure('sync_pft_transaction_history')
    async def sync_pft_transaction_history(self, is_initial_sync: bool = True) -> StateSyncStats:
        """Synchronize and verify PFT state.
        
        This method:
        1. Fetches all PFT holder accounts from XRPL
        2. Syncs missing transactions for each account
        3. Verifies and corrects database balances against XRPL state
        4. Queues any unprocessed transactions for review

        Args:
        is_initial_sync: If True, this is the initial sync at application startup.
                        If False, this is a periodic verification check.
        
        Returns:
            StateSyncStats: Statistics about the sync/verification process
        """
        BATCH_SIZE = 100
        state_sync_stats = StateSyncStats()

        log_prefix = "Initial sync" if is_initial_sync else "Periodic sync"
        logger.info(f"{log_prefix}: Starting PFT state synchronization...")

        # Get all PFT holder accounts
        trustline_data = await self.generic_pft_utilities.fetch_pft_trustline_data()
        all_accounts = list(trustline_data.keys())
        total_accounts = len(all_accounts)

        logger.info(f"Starting transaction history sync for {total_accounts} accounts")

        for idx, account in enumerate(all_accounts, 1):
            try:
                tx_hist = await self.generic_pft_utilities.fetch_formatted_transaction_history(account_address=account)

                if tx_hist:
                    # Process transactions in batches of BATCH_SIZE
                    total_rows_inserted = 0
                    try:
                        for batch in self._get_transaction_batches(tx_hist, batch_size=BATCH_SIZE):
                            inserted = await self.transaction_repository.batch_insert_transactions(batch)
                            total_rows_inserted += inserted

                        if total_rows_inserted > 0:
                            state_sync_stats.transactions_found += total_rows_inserted
                            state_sync_stats.accounts_with_missing_data += 1
                            state_sync_stats.rows_inserted += total_rows_inserted

                            if not is_initial_sync:
                                logger.warning(
                                    f"{log_prefix}: Found {total_rows_inserted} missing transactions "
                                    f"for account {account} - possible websocket drop"
                                )

                    except Exception as e:
                        logger.error(f"Error in batch insert for account {account}: {e}")
                        logger.error(traceback.format_exc())
                        continue
                
                # Verify balance against database
                db_holder = await self.transaction_repository.get_pft_holder(account)
                xrpl_balance = trustline_data[account]['pft_holdings']

                # Handle missing or mismatched database records
                if db_holder is None:
                    if xrpl_balance != Decimal(0):
                        if not is_initial_sync:
                            logger.warning(
                                f"{log_prefix}: Account {account} has XRPL balance of "
                                f"{xrpl_balance} PFT but no database record - possible websocket drop"
                            )
                        state_sync_stats.balance_mismatches += 1
                        await self.transaction_repository.update_pft_holder(
                            account=account,
                            balance=xrpl_balance,
                            last_tx_hash=None
                        )
                        state_sync_stats.balances_corrected += 1
                else:
                    db_balance = db_holder['balance']
                    if xrpl_balance != db_balance:
                        if not is_initial_sync:
                            logger.warning(
                                f"{log_prefix}: Balance mismatch for account {account}: "
                                f"XRPL: {xrpl_balance} PFT, Database: {db_balance} PFT - possible websocket drop"
                            )
                        state_sync_stats.balance_mismatches += 1
                        await self.transaction_repository.update_pft_holder(
                            account=account,
                            balance=xrpl_balance,
                            last_tx_hash=db_holder.get('last_tx_hash')
                        )
                        state_sync_stats.balances_corrected += 1

                state_sync_stats.accounts_processed += 1

                # Log progress every 5 accounts
                if idx % 5 == 0:
                    progress = (idx / total_accounts) * 100
                    logger.debug(
                        f"{log_prefix}: Progress: {progress:.1f}% - "
                        f"Synced {idx}/{total_accounts} accounts, "
                        f"{state_sync_stats.rows_inserted} rows inserted"
                    )
                    
            except Exception as e:
                logger.error(f"{log_prefix}: Error processing account {account}: {e}")
                logger.error(traceback.format_exc())
                continue
                
        logger.info(
            f"{log_prefix}: Completed. Processed {state_sync_stats.accounts_processed}/{total_accounts} "
            f"accounts, inserted {state_sync_stats.rows_inserted} rows, "
            f"found {state_sync_stats.transactions_found} new transactions, "
            f"corrected {state_sync_stats.balances_corrected} balances"
        )

        return state_sync_stats

    async def queue_unprocessed_transactions(self):
        """Queue any unprocessed transactions for review.
    
        Returns:
            int: Number of transactions queued
        """
        logger.debug("TransactionOrchestrator: Getting unprocessed transactions")
        unprocessed_txs = await self.transaction_repository.get_unprocessed_transactions(
            order_by="close_time_iso ASC",
            include_processed=False   # Set to True for debugging only
        )
        logger.debug(f"TransactionOrchestrator: Found {len(unprocessed_txs)} unprocessed transactions")

        for tx in unprocessed_txs:
            await self.review_queue.put(tx)

    async def _state_sync_loop(self):
        """Handles initial and periodic state synchronization between XRPL and local database"""
        try:
            while not self._shutdown_event.is_set():
                try:
                    is_initial_sync = not self._initial_sync_complete

                    # Run state verification
                    state_sync_stats = await self.sync_pft_transaction_history(
                        is_initial_sync=is_initial_sync
                    )

                    # Queue any unprocessed transactions if 
                    # 1. It's the initial sync
                    # 2. It's not the initial sync and new transactions were inserted into the cache
                    if not self._initial_sync_complete or (state_sync_stats.rows_inserted > 0 and self._initial_sync_complete):
                        await self.queue_unprocessed_transactions()

                    # Mark initial sync complete after first run
                    if is_initial_sync:
                        self._initial_sync_complete = True
                    else:
                        if any(v > 0 for k, v in vars(state_sync_stats).items() if k != 'accounts_processed'):
                            logger.warning(
                                "Periodic sync found inconsistencies: "
                                f"{state_sync_stats.transactions_found} missing transactions, "
                                f"{state_sync_stats.balance_mismatches} balance mismatches "
                                f"(corrected {state_sync_stats.balances_corrected})"
                            )

                except Exception as e:
                    logger.error(f"Error in state sync loop: {e}")
                    logger.error(traceback.format_exc())
                    await asyncio.sleep(60)  # Wait a minute before retrying if there's an error

                await asyncio.sleep(VERIFY_STATE_INTERVAL)

        except asyncio.CancelledError:
            logger.info("State sync loop shutdown requested")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in state sync loop: {e}")
            logger.error(traceback.format_exc())
            raise

    async def _review_loop(self):
        """Continuously review transactions from the review queue"""
        reviewed_count = 0
        unprocessed_count = 0
        last_activity_time = time.time()
        IDLE_LOG_INTERVAL = 3600  # Log idle status every 60 minutes
        COUNT_LOG_INTERVAL = 500  # Log count every 500 transactions

        try:
            while not self._shutdown_event.is_set():
                try:
                    # Wait for next transaction with timeout
                    tx = await asyncio.wait_for(self.review_queue.get(), timeout=IDLE_LOG_INTERVAL)

                    # Skip invalid transactions
                    if not tx or not tx.get('hash'):
                        logger.warning(f"TransactionOrchestrator: Skipping invalid transaction: {tx}")
                        continue
                    
                    # Review transaction. Result includes the transaction post-processing (result.tx)
                    result = await self.reviewer.review_transaction(tx)
                    await self.transaction_repository.store_reviewing_result(result)

                    # If transaction needs a response, add to processing queue
                    if not result.processed:
                        unprocessed_count += 1
                        logger.debug(f"TransactionOrchestrator: Transaction {result.tx['hash']} with memo type {result.tx['memo_type']} needs a response.")
                        await self.routing_queue.put(result.tx)

                    # Update counts and handle logging
                    reviewed_count += 1
                    last_activity_time = time.time()

                    # Check if queue just became empty
                    queue_size = self.review_queue.qsize()
                    if queue_size == 0:
                        self.reviewer.end_sync_mode()
                        logger.info(f"Finished reviewing. Total transactions reviewed: {reviewed_count}. Total transactions needing a response: {unprocessed_count}")

                    if reviewed_count % COUNT_LOG_INTERVAL == 0:
                        logger.debug(f"Progress: {reviewed_count} transactions reviewed. Current queue size: {queue_size}")

                except asyncio.TimeoutError:
                    current_time = time.time()
                    idle_duration = current_time - last_activity_time
                    logger.debug(f"TransactionOrchestrator: Review loop idle for {format_duration(idle_duration)}. Total reviewed: {reviewed_count}")
                    continue
                    
                except Exception as e:
                    logger.error(f"Error reviewing transaction: {e}")
                    logger.error(traceback.format_exc())
                    logger.error(f"Transaction: {tx}")

        finally:
            logger.debug("TransactionOrchestrator: Review loop shutdown complete")

    async def _route_loop(self):
        """Continuously route transactions that need responses"""
        routed_count = 0
        last_activity_time = time.time()
        IDLE_LOG_INTERVAL = 3600  # Log idle status every 60 minutes
        ROUTE_LOG_INTERVAL = 100  # Log count every 100 transactions

        try:
            while not self._shutdown_event.is_set():
                try:
                    # Wait for next transaction with timeout
                    tx = await asyncio.wait_for(self.routing_queue.get(), timeout=IDLE_LOG_INTERVAL)
                    
                    # Route transaction to appropriate response queue
                    routed = await self.response_manager.route_transaction(tx)
                    if routed:
                        routed_count += 1
                        last_activity_time = time.time()

                    # Log progress by count
                    queue_size = self.routing_queue.qsize()
                    if queue_size == 0:
                        logger.info(f"Finished routing. Total routed: {routed_count}.")

                    if routed_count % ROUTE_LOG_INTERVAL == 0:
                        queue_size = self.routing_queue.qsize()
                        logger.debug(f"TransactionOrchestrator: Progress: {routed_count} transactions routed. Current queue size: {queue_size}")

                except asyncio.TimeoutError:
                    current_time = time.time()
                    idle_duration = current_time - last_activity_time
                    pending_count = len(self.response_manager.pending_responses)
                    logger.debug(
                        f"TransactionOrchestrator: Route loop idle for {format_duration(idle_duration)}.\n"
                        f"  - Total routed: {routed_count}\n"
                        f"  - Pending responses: {pending_count}\n"
                        f"  - Routing queue size: {self.routing_queue.qsize()}"
                    )
                    continue
                    
                except Exception as e:
                    logger.error(f"Error routing transaction: {e}")
                    logger.error(traceback.format_exc())

        finally:
            logger.debug("TransactionOrchestrator: Route loop shutdown complete")

    async def _consumer_loop(self):
        """Manage consumer lifecycle"""
        try:
            await self.consumer_manager.start()
            await self._shutdown_event.wait()  # Wait for shutdown signal
        except Exception as e:
            logger.error(f"Error in consumer loop: {e}")
            logger.error(traceback.format_exc())
        finally:
            await self.consumer_manager.stop()
            logger.debug("TransactionOrchestrator: Consumer loop shutdown complete")

    def stop(self):
        """Synchronous method to stop the orchestrator"""
        try:
            # Get or create event loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop.run_until_complete(self._stop_async())
            
            # If we already had a running loop, create a task
            return loop.create_task(self._stop_async())

        except Exception as e:
            logger.error(f"TransactionOrchestrator: Error during synchronous stop: {e}")
            logger.error(traceback.format_exc())
            raise

    async def _stop_async(self):
        """Gracefully stop all transaction processing tasks"""
        logger.debug("TransactionOrchestrator: Initiating shutdown")
        self._shutdown_event.set()

        if not self._managed_tasks:
            return
        
        try:
            # Stop XRPL monitor
            self.xrpl_monitor.stop()

            # First, stop managed tasks
            if self._managed_tasks:
                done, pending = await asyncio.wait(
                    self._managed_tasks, 
                    timeout=self.SHUTDOWN_TIMEOUT
                )

                if pending:
                    pending_names = [f"{task.get_name()} ({id(task)})" for task in pending]
                    logger.warning(
                        f"Timeout waiting for managed tasks to shutdown gracefully: "
                        f"{', '.join(pending_names)}"
                    )
                    for task in pending:
                        task.cancel()

                    # Give cancelled tasks a moment to clean up
                    try:
                        await asyncio.wait(pending, timeout=self.SHUTDOWN_TIMEOUT)
                    except asyncio.TimeoutError:
                        logger.error("Some tasks could not be cancelled")

        except Exception as e:
            logger.error(f"TransactionOrchestrator: Error during shutdown: {e}")
            logger.error(traceback.format_exc())
        finally:
            self._managed_tasks.clear()
            logger.info("TransactionOrchestrator: Shutdown complete")