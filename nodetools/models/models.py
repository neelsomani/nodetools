from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Set, Optional, Dict, Any, Pattern, TYPE_CHECKING, List
from enum import Enum
from loguru import logger
from decimal import Decimal
from xrpl.models import Memo
import re

if TYPE_CHECKING:
    from nodetools.protocols.credentials import CredentialManager
    from nodetools.protocols.generic_pft_utilities import GenericPFTUtilities
    from nodetools.protocols.openrouter import OpenRouterTool
    from nodetools.protocols.transaction_repository import TransactionRepository
    from nodetools.protocols.encryption import MessageEncryption
    from nodetools.protocols.db_manager import DBConnectionManager
    from nodetools.configuration.configuration import NodeConfig, NetworkConfig
    from nodetools.protocols.openai_request import OpenAIRequestTool

class InteractionType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    STANDALONE = "standalone"

class MemoDataStructureType(Enum):
    ECDH = "e"      # Encryption
    BROTLI = "b"    # Compression
    CHUNK = "c"     # Chunking
    NONE = "-"      # No processing

@dataclass
class Dependencies:
    """Container for core dependencies that can be provided by NodeTools"""
    network_config: 'NetworkConfig'
    node_config: 'NodeConfig'
    credential_manager: 'CredentialManager'
    generic_pft_utilities: 'GenericPFTUtilities'
    openrouter: 'OpenRouterTool'
    transaction_repository: 'TransactionRepository'
    message_encryption: 'MessageEncryption'
    openai: 'OpenAIRequestTool'

@dataclass
class MemoStructure:
    """Describes how a memo is structured across transactions"""
    is_chunked: bool
    chunk_index: Optional[int] = None
    total_chunks: Optional[int] = None
    group_id: Optional[str] = None
    compression_type: Optional[MemoDataStructureType] = None  # Might be unknown until processing
    encryption_type: Optional[MemoDataStructureType] = None   # Might be unknown until processing
    is_standardized_format: bool = False  

    @property
    def is_complete(self) -> bool:
        """Whether this represents a complete memo"""
        return not self.is_chunked  # A non-chunked memo is always complete
    
    @classmethod
    def is_standardized_memo_format(cls, memo_format: Optional[str]) -> bool:
        """
        Check if memo_format follows the standardized format.
        Examples:
            "e.b.c1/4"  # encrypted, compressed, chunk 1 of 4
            "-.b.c2/4"  # not encrypted, compressed, chunk 2 of 4
            "-.-.-"     # no special processing
        """
        if not memo_format:
            return False
        
        parts = memo_format.split(".")
        if len(parts) != 3:
            return False
        
        encryption, compression, chunking = parts

        # Validate encryption part
        if encryption not in {MemoDataStructureType.ECDH.value, MemoDataStructureType.NONE.value}:
            return False
            
        # Validate compression part
        if compression not in {MemoDataStructureType.BROTLI.value, MemoDataStructureType.NONE.value}:
            return False
            
        # Validate chunking part
        if chunking != MemoDataStructureType.NONE.value:
            chunk_match = re.match(fr'{MemoDataStructureType.CHUNK.value}\d+/\d+', chunking)
            if not chunk_match:
                return False
                
        return True
    
    @classmethod
    def parse_standardized_format(cls, memo_format: str) -> 'MemoStructure':
        """Parse a validated standardized memo_format string."""
        encryption, compression, chunking = memo_format.split(".")

        # Parse encryption
        encryption_type = (
            MemoDataStructureType.ECDH if encryption == MemoDataStructureType.ECDH.value 
            else None
        )
        
        # Parse compression
        compression_type = (
            MemoDataStructureType.BROTLI if compression == MemoDataStructureType.BROTLI.value 
            else None
        )
        
        # Parse chunking
        chunk_index = None
        total_chunks = None
        if chunking != MemoDataStructureType.NONE.value:
            chunk_match = re.match(fr'{MemoDataStructureType.CHUNK.value}(\d+)/(\d+)', chunking)
            if chunk_match:  # We know this matches from validation
                chunk_index = int(chunk_match.group(1))
                total_chunks = int(chunk_match.group(2))
        
        return cls(
            is_chunked=chunk_index is not None,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            group_id=None,  # Will be set from tx
            compression_type=compression_type,
            encryption_type=encryption_type,
            is_standardized_format=True
        )
    
    @classmethod
    def from_transaction(cls, tx: Dict[str, Any]) -> 'MemoStructure':
        """
        Extract memo structure from transaction memo fields.
        
        New format examples:
            "e.b.c1/4"                    # encrypted, compressed, chunk 1 of 4
            "-.b.c2/4"                    # not encrypted, compressed, chunk 2 of 4
            "-.-.-"                       # no special processing
            "invalid_format"              # Invalid - will fall back to legacy
        
        Legacy format example: 
            memo_data with "chunk_1__" prefix and nested "COMPRESSED__" and "WHISPER__" prefixes

        Legacy format caveats:
        1. COMPRESSED__ prefix only appears in first chunk
        2. WHISPER__ prefix only visible after decompression
        3. Structure might need to be updated after processing
        
        Examples:
            First chunk:  "chunk_1__COMPRESSED__<compressed_data>"
            Other chunks: "chunk_2__<compressed_data>"
            After joining and decompressing: "WHISPER__<encrypted_data>"
        """
        memo_data = tx.get("memo_data", "")
        memo_format = tx.get("memo_format")

        # Check if using standardized format
        if cls.is_standardized_memo_format(memo_format):
            structure = cls.parse_standardized_format(memo_format)
            structure.group_id = tx.get("memo_type")  # Set group_id from transaction
            return structure

        ## Backwards compatibility for legacy format
        # Fall back to legacy prefix detection
        chunk_match = re.match(r'^chunk_(\d+)__', memo_data)
        
        # Only check compression on first chunk
        is_compressed = (
            "COMPRESSED__" in memo_data 
            if chunk_match and chunk_match.group(1) == "1" 
            else None  # Unknown for other chunks
        )

        return cls(
            is_chunked=chunk_match is not None,
            chunk_index=int(chunk_match.group(1)) if chunk_match else None,
            total_chunks=None,  # Legacy format doesn't specify total chunks
            group_id=tx.get("memo_type"),
            compression_type=MemoDataStructureType.BROTLI if is_compressed else None,
            encryption_type=None,  # Will be determined after processing
            is_standardized_format=False
        )
    
@dataclass
class MemoGroup:
    """
    Manages a group of related memos from individual transactions.
    Memos are related if they share the same memo_type (group_id) and have a consistent memo_format (MemoStructure).
    These memos can be reconstituted into a single memo by unchunking.
    Additional processing can be applied to the unchunked memo_data.
    """
    group_id: str
    memos: List[Dict[str, Any]]
    structure: Optional[MemoStructure] = None

    @classmethod
    def create_from_transaction(cls, tx: Dict[str, Any]) -> 'MemoGroup':
        """Create a new message group from an initial transaction"""
        structure = MemoStructure.from_transaction(tx)
        return cls(
            group_id=tx.get("memo_type"),
            memos=[tx],
            structure=structure,
        )
    
    def _is_structure_consistent(self, new_structure: MemoStructure) -> bool:
        """
        Check if a new message's structure is consistent with the group.
        Only applies to new format messages, whose structure can be interpreted from memo_format.
        """            
        return (
            new_structure.encryption_type == self.structure.encryption_type and
            new_structure.compression_type == self.structure.compression_type and
            new_structure.total_chunks == self.structure.total_chunks
        )
    
    def add_memo(self, tx: Dict[str, Any]) -> bool:
        """
        Add a memo to the group if it belongs.
        Returns True if memo was added, False if it doesn't belong.
        """
        if tx.get('transaction_result') != 'tesSUCCESS':
            return False

        if tx.get("memo_type") != self.group_id:
            return False
        
        new_structure = MemoStructure.from_transaction(tx)

        # For new format messages, validate consistency
        if new_structure.is_standardized_format:
            if not self._is_structure_consistent(new_structure):
                logger.warning(f"Inconsistent message structure in group {self.group_id}")
                return False
            self.memos.append(tx)
            return True
        
        # For legacy format messages, handle duplicate chunks
        if new_structure.chunk_index is not None:
            # Find any existing memo with the same chunk index
            existing_memo = next(
                (memo for memo in self.memos 
                if MemoStructure.from_transaction(memo).chunk_index == new_structure.chunk_index),
                None
            )
            
            if existing_memo:
                # If we found a duplicate chunk, only replace if new tx has earlier datetime
                if tx.get('datetime') < existing_memo.get('datetime'):
                    self.memos.remove(existing_memo)
                    self.memos.append(tx)
                    return True
                return False  # Duplicate chunk with later datetime, ignore it
        
        # No duplicate found, add the new memo
        self.memos.append(tx)
        return True
        
    @property
    def chunk_indices(self) -> Set[int]:
        """Get set of available chunk indices"""
        return {
            MemoStructure.from_transaction(tx).chunk_index
            for tx in self.memos
            if MemoStructure.from_transaction(tx).chunk_index is not None
        }
    
class StructuralPattern(Enum):
    """
    Defines patterns for matching XRPL memo structure before content processing.
    Used to determine if memos need grouping and how they should be processed.
    """
    NO_MEMO = "no_memo"                    # No memo present  
    DIRECT_MATCH = "direct_match"          # Can be pattern matched directly
    NEEDS_GROUPING = "needs_grouping"      # New format, needs grouping
    NEEDS_LEGACY_GROUPING = "needs_legacy_grouping"  # Legacy format, needs grouping

    @staticmethod
    def match(tx: Dict[str, Any]) -> str:
        """Determine how a transaction's memos should be handled"""
        if not bool(tx.get('has_memos')):
            return StructuralPattern.NO_MEMO

        # Check if there is no memo present
        structure = MemoStructure.from_transaction(tx)
        if structure.is_standardized_format:
            # New format: Use metadata to determine grouping needs
            return StructuralPattern.NEEDS_GROUPING if structure.is_chunked else StructuralPattern.DIRECT_MATCH
        else:
            # Legacy format: Check for chunk prefix
            if "chunk_" in tx.get('memo_data', ''):
                return StructuralPattern.NEEDS_LEGACY_GROUPING
            return StructuralPattern.DIRECT_MATCH

@dataclass(frozen=True)  # Making it immutable for hashability
class MemoPattern:
    """
    Defines patterns for matching processed XRPL memos.
    Matching occurs after any necessary unchunking/decompression/decryption.
    """
    memo_type: Optional[str | Pattern] = None
    memo_format: Optional[str | Pattern] = None
    memo_data: Optional[str | Pattern] = None

    def get_message_structure(self, tx: Dict[str, Any]) -> MemoStructure:
        """Extract structural information from the memo fields"""
        return MemoStructure.from_transaction(tx)

    def matches(self, tx: Dict[str, Any]) -> bool:
        """Check if a transaction's memo matches this pattern"""
        if self.memo_type:
            tx_memo_type = tx.get("memo_type")
            if not tx_memo_type or not self._pattern_matches(self.memo_type, tx_memo_type):
                return False

        if self.memo_format:
            tx_memo_format = tx.get("memo_format")
            if not tx_memo_format or not self._pattern_matches(self.memo_format, tx_memo_format):
                return False

        if self.memo_data:
            tx_memo_data = tx.get("memo_data")
            if not tx_memo_data or not self._pattern_matches(self.memo_data, tx_memo_data):
                return False

        return True

    def _pattern_matches(self, pattern: str | Pattern, value: str) -> bool:
        if isinstance(pattern, Pattern):
            return bool(pattern.match(value))
        return pattern == value
    
    def __hash__(self):
        # Convert Pattern objects to their pattern strings for hashing
        memo_type_hash = self.memo_type.pattern if isinstance(self.memo_type, Pattern) else self.memo_type
        memo_format_hash = self.memo_format.pattern if isinstance(self.memo_format, Pattern) else self.memo_format
        memo_data_hash = self.memo_data.pattern if isinstance(self.memo_data, Pattern) else self.memo_data
        
        return hash((memo_type_hash, memo_format_hash, memo_data_hash))
    
    def __eq__(self, other):
        if not isinstance(other, MemoPattern):
            return False
        
        # Compare Pattern objects by their pattern strings
        def compare_attrs(a, b):
            if isinstance(a, Pattern) and isinstance(b, Pattern):
                return a.pattern == b.pattern
            return a == b
        
        return (compare_attrs(self.memo_type, other.memo_type) and
                compare_attrs(self.memo_format, other.memo_format) and
                compare_attrs(self.memo_data, other.memo_data))

@dataclass
class InteractionPattern:
    memo_pattern: MemoPattern
    transaction_type: InteractionType
    valid_responses: Set[MemoPattern]
    notify: bool = False

    def __post_init__(self):
        # Validate that RESPONSE types don't have valid_responses
        if self.transaction_type == InteractionType.RESPONSE and self.valid_responses:
            raise ValueError("RESPONSE types cannot have valid_responses")
        # Validate that REQUEST types must have valid_responses
        if self.transaction_type == InteractionType.REQUEST and not self.valid_responses:
            raise ValueError("REQUEST types must have valid_responses")

class InteractionGraph:
    def __init__(self):
        self.patterns: Dict[str, InteractionPattern] = {}
        self.memo_pattern_to_id: Dict[MemoPattern, str] = {}

    def add_pattern(
            self,
            pattern_id: str,
            memo_pattern: MemoPattern,
            transaction_type: InteractionType,
            valid_responses: Optional[Set[MemoPattern]] = None,
            notify: bool = False
    ) -> None:
        """
        Add a new pattern to the graph.
        For RESPONSE and STANDALONE types, valid_responses should be None or empty.
        For REQUEST types, valid_responses must be provided.

        Args:
            pattern_id: Unique identifier for the pattern
            memo_pattern: The memo pattern to match
            transaction_type: Type of interaction (REQUEST/RESPONSE/STANDALONE)
            valid_responses: Set of valid response patterns (required for REQUEST type)
            notify: Whether transactions matching this pattern should trigger notifications
        """
        self.patterns[pattern_id] = InteractionPattern(
            memo_pattern=memo_pattern, 
            transaction_type=transaction_type, 
            valid_responses=valid_responses,
            notify=notify
        )
        # Update the reverse lookup
        self.memo_pattern_to_id[memo_pattern] = pattern_id

    def is_valid_response(self, request_pattern_id: str, response_tx: Dict[str, Any]) -> bool:
        if request_pattern_id not in self.patterns:
            return False
        
        pattern = self.patterns[request_pattern_id]
        if pattern.transaction_type != InteractionType.REQUEST:
            return False

        return any(resp_pattern.matches(response_tx) for resp_pattern in pattern.valid_responses)

    def find_matching_pattern(self, tx: Dict[str, Any]) -> Optional[str]:
        """Find the first pattern ID whose pattern matches the transaction"""
        for pattern_id, pattern in self.patterns.items():
            if pattern.memo_pattern.matches(tx):
                return pattern_id
            continue
        return None
    
    def get_pattern_id_by_memo_pattern(self, memo_pattern: MemoPattern) -> Optional[str]:
        """Get the pattern ID for a given memo pattern"""
        return self.memo_pattern_to_id.get(memo_pattern)

class InteractionRule(ABC):
    """Base class for interaction processing rules"""
    transaction_type: InteractionType

    @abstractmethod
    async def validate(self, tx: Dict[str, Any], *args, **kwargs) -> bool:
        """
        Validate any additional business rules for an interaction
        This is separate from the interaction pattern matching
        """
        pass

@dataclass
class ResponseQuery:
    """Data class to hold query information for finding responses"""
    query: str
    params: Dict[str, Any]

class RequestRule(InteractionRule):
    """Base class for rules that handle request transactions"""
    transaction_type = InteractionType.REQUEST

    @abstractmethod
    async def validate(
        self,
        tx: Dict[str, Any],
        dependencies: Dependencies
    ) -> bool:
        """Validate transaction against business rules"""
        pass

    @abstractmethod
    async def find_response(self, request_tx: Dict[str, Any]) -> Optional[ResponseQuery]:
        """Get query information for finding a valid response transaction"""
        pass

@dataclass
class ResponseParameters:
    """Standardized response parameters for transaction construction"""
    source: str  # Name of the address that should send the response
    memo: Memo  # XRPL memo object
    destination: str  # XRPL destination address
    pft_amount: Optional[Decimal] = None  # Optional PFT amount for the transaction

class ResponseGenerator(ABC):
    """Abstract base class defining how to generate a response"""
    @abstractmethod
    async def evaluate_request(self, request_tx: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate the request and return response parameters"""
        pass

    @abstractmethod
    async def construct_response(
        self, 
        request_tx: Dict[str, Any],
        evaluation_result: Dict[str, Any]
    ) -> ResponseParameters:
        """Construct the response memo and parameters"""
        pass

class ResponseRule(InteractionRule):
    """Base class for rules that handle response transactions"""
    transaction_type = InteractionType.RESPONSE

    @abstractmethod
    def get_response_generator(self, *args, **kwargs) -> ResponseGenerator:
        """
        Get the response generator for this rule type.
        
        Each rule implementation should document its required dependencies.
        """
        pass

class StandaloneRule(InteractionRule):
    """Base class for rules that handle standalone transactions"""
    transaction_type = InteractionType.STANDALONE
    
@dataclass
class BusinessLogicProvider(ABC):
    """Abstract base class that defines required business logic interface"""
    transaction_graph: InteractionGraph
    pattern_rule_map: Dict[str, InteractionRule]  # Maps pattern_id to rule instance

    @classmethod
    @abstractmethod
    def create(cls) -> 'BusinessLogicProvider':
        """Factory method that implementations must provide"""
        pass
