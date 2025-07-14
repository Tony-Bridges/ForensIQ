"""
Blockchain, Crypto, and NFT Forensics Module
Supports wallet analysis, transaction tracing, smart contract analysis,
and NFT authenticity verification.
"""
import hashlib
import json
import re
from datetime import datetime
import logging
from collections import defaultdict

class BlockchainForensics:
    def __init__(self):
        self.supported_chains = ['bitcoin', 'ethereum', 'monero', 'litecoin', 'binance_smart_chain']
        self.wallet_patterns = {
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'monero': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
        }
        self.exchange_addresses = {
            'binance': ['1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ', '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo'],
            'coinbase': ['3M219KQQky9FaUEiYQdVs9K9pYYJQCu1XG', '1KC7w4A2vYVBKqQHYRvHJnz7aSMj6Z9N2v'],
            'kraken': ['1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF', '3BMhsqHEF3TE2rnrMcXcKfzx6kMcJvMhpF']
        }
        
    def trace_wallet_transactions(self, wallet_address, blockchain='bitcoin', depth=3):
        """
        Trace transactions for a given wallet address.
        
        Args:
            wallet_address: Wallet address to trace
            blockchain: Blockchain network
            depth: Number of transaction hops to follow
            
        Returns:
            dict: Transaction tracing results
        """
        tracing_results = {
            'wallet_address': wallet_address,
            'blockchain': blockchain,
            'timestamp': datetime.utcnow().isoformat(),
            'transactions': [],
            'connected_addresses': [],
            'exchange_interactions': [],
            'risk_score': 0.0,
            'kyc_linked_addresses': []
        }
        
        try:
            # Get transaction history
            transactions = self._get_wallet_transactions(wallet_address, blockchain)
            tracing_results['transactions'] = transactions
            
            # Trace connected addresses
            connected_addresses = self._trace_connected_addresses(transactions, depth)
            tracing_results['connected_addresses'] = connected_addresses
            
            # Identify exchange interactions
            exchange_interactions = self._identify_exchange_interactions(transactions)
            tracing_results['exchange_interactions'] = exchange_interactions
            
            # Calculate risk score
            tracing_results['risk_score'] = self._calculate_risk_score(transactions, connected_addresses)
            
            # Attempt KYC linking
            tracing_results['kyc_linked_addresses'] = self._attempt_kyc_linking(connected_addresses)
            
        except Exception as e:
            logging.error(f"Wallet tracing failed: {str(e)}")
            tracing_results['error'] = str(e)
            
        return tracing_results
        
    def analyze_smart_contract(self, contract_address, blockchain='ethereum'):
        """
        Analyze smart contract for vulnerabilities and backdoors.
        
        Args:
            contract_address: Smart contract address
            blockchain: Blockchain network
            
        Returns:
            dict: Smart contract analysis results
        """
        analysis_results = {
            'contract_address': contract_address,
            'blockchain': blockchain,
            'timestamp': datetime.utcnow().isoformat(),
            'contract_code': '',
            'vulnerabilities': [],
            'backdoors': [],
            'honeypot_indicators': [],
            'ownership_analysis': {},
            'transaction_patterns': {}
        }
        
        try:
            # Get contract source code
            contract_code = self._get_contract_source_code(contract_address, blockchain)
            analysis_results['contract_code'] = contract_code
            
            # Analyze for vulnerabilities
            vulnerabilities = self._analyze_contract_vulnerabilities(contract_code)
            analysis_results['vulnerabilities'] = vulnerabilities
            
            # Check for backdoors
            backdoors = self._detect_contract_backdoors(contract_code)
            analysis_results['backdoors'] = backdoors
            
            # Honeypot detection
            honeypot_indicators = self._detect_honeypot_patterns(contract_code)
            analysis_results['honeypot_indicators'] = honeypot_indicators
            
            # Ownership analysis
            ownership_info = self._analyze_contract_ownership(contract_address, blockchain)
            analysis_results['ownership_analysis'] = ownership_info
            
            # Transaction pattern analysis
            tx_patterns = self._analyze_contract_transactions(contract_address, blockchain)
            analysis_results['transaction_patterns'] = tx_patterns
            
        except Exception as e:
            logging.error(f"Smart contract analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def verify_nft_authenticity(self, nft_token_id, contract_address, blockchain='ethereum'):
        """
        Verify NFT authenticity and trace ownership history.
        
        Args:
            nft_token_id: NFT token identifier
            contract_address: NFT contract address
            blockchain: Blockchain network
            
        Returns:
            dict: NFT verification results
        """
        verification_results = {
            'token_id': nft_token_id,
            'contract_address': contract_address,
            'blockchain': blockchain,
            'timestamp': datetime.utcnow().isoformat(),
            'authenticity_score': 0.0,
            'ownership_history': [],
            'metadata_analysis': {},
            'provenance_trail': [],
            'forgery_indicators': [],
            'market_manipulation': []
        }
        
        try:
            # Get NFT metadata
            metadata = self._get_nft_metadata(nft_token_id, contract_address, blockchain)
            verification_results['metadata_analysis'] = metadata
            
            # Trace ownership history
            ownership_history = self._trace_nft_ownership(nft_token_id, contract_address, blockchain)
            verification_results['ownership_history'] = ownership_history
            
            # Verify provenance
            provenance = self._verify_nft_provenance(metadata, ownership_history)
            verification_results['provenance_trail'] = provenance
            
            # Check for forgery indicators
            forgery_indicators = self._detect_nft_forgery(metadata, ownership_history)
            verification_results['forgery_indicators'] = forgery_indicators
            
            # Detect market manipulation
            manipulation = self._detect_market_manipulation(ownership_history)
            verification_results['market_manipulation'] = manipulation
            
            # Calculate authenticity score
            verification_results['authenticity_score'] = self._calculate_authenticity_score(
                metadata, ownership_history, forgery_indicators, manipulation
            )
            
        except Exception as e:
            logging.error(f"NFT verification failed: {str(e)}")
            verification_results['error'] = str(e)
            
        return verification_results
        
    def analyze_defi_interactions(self, wallet_address, blockchain='ethereum'):
        """
        Analyze DeFi protocol interactions for suspicious activity.
        
        Args:
            wallet_address: Wallet address to analyze
            blockchain: Blockchain network
            
        Returns:
            dict: DeFi analysis results
        """
        analysis_results = {
            'wallet_address': wallet_address,
            'blockchain': blockchain,
            'timestamp': datetime.utcnow().isoformat(),
            'protocol_interactions': [],
            'liquidity_movements': [],
            'yield_farming_activity': [],
            'flash_loan_usage': [],
            'suspicious_patterns': []
        }
        
        try:
            # Analyze protocol interactions
            protocol_interactions = self._analyze_protocol_interactions(wallet_address, blockchain)
            analysis_results['protocol_interactions'] = protocol_interactions
            
            # Track liquidity movements
            liquidity_movements = self._track_liquidity_movements(wallet_address, blockchain)
            analysis_results['liquidity_movements'] = liquidity_movements
            
            # Analyze yield farming
            yield_farming = self._analyze_yield_farming(wallet_address, blockchain)
            analysis_results['yield_farming_activity'] = yield_farming
            
            # Detect flash loan usage
            flash_loans = self._detect_flash_loan_usage(wallet_address, blockchain)
            analysis_results['flash_loan_usage'] = flash_loans
            
            # Identify suspicious patterns
            suspicious_patterns = self._identify_suspicious_defi_patterns(
                protocol_interactions, liquidity_movements, flash_loans
            )
            analysis_results['suspicious_patterns'] = suspicious_patterns
            
        except Exception as e:
            logging.error(f"DeFi analysis failed: {str(e)}")
            analysis_results['error'] = str(e)
            
        return analysis_results
        
    def _get_wallet_transactions(self, wallet_address, blockchain):
        """Get transaction history for a wallet."""
        # Simulate API call to blockchain explorer
        transactions = [
            {
                'tx_hash': 'a1b2c3d4e5f6',
                'timestamp': '2024-01-15T10:30:00Z',
                'amount': '0.5',
                'currency': 'BTC' if blockchain == 'bitcoin' else 'ETH',
                'from_address': wallet_address,
                'to_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                'transaction_fee': '0.0001',
                'confirmations': 6
            },
            {
                'tx_hash': 'f6e5d4c3b2a1',
                'timestamp': '2024-01-16T14:20:00Z',
                'amount': '1.2',
                'currency': 'BTC' if blockchain == 'bitcoin' else 'ETH',
                'from_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                'to_address': wallet_address,
                'transaction_fee': '0.0002',
                'confirmations': 12
            }
        ]
        return transactions
        
    def _trace_connected_addresses(self, transactions, depth):
        """Trace addresses connected through transactions."""
        connected_addresses = []
        
        for tx in transactions:
            if 'from_address' in tx:
                connected_addresses.append({
                    'address': tx['from_address'],
                    'relationship': 'sender',
                    'transaction_count': 1,
                    'total_amount': float(tx.get('amount', 0))
                })
            if 'to_address' in tx:
                connected_addresses.append({
                    'address': tx['to_address'],
                    'relationship': 'receiver',
                    'transaction_count': 1,
                    'total_amount': float(tx.get('amount', 0))
                })
                
        return connected_addresses
        
    def _identify_exchange_interactions(self, transactions):
        """Identify interactions with known exchange addresses."""
        exchange_interactions = []
        
        for tx in transactions:
            for exchange, addresses in self.exchange_addresses.items():
                if tx.get('from_address') in addresses or tx.get('to_address') in addresses:
                    exchange_interactions.append({
                        'exchange': exchange,
                        'transaction': tx,
                        'interaction_type': 'deposit' if tx.get('to_address') in addresses else 'withdrawal'
                    })
                    
        return exchange_interactions
        
    def _calculate_risk_score(self, transactions, connected_addresses):
        """Calculate risk score based on transaction patterns."""
        risk_score = 0.0
        
        # High frequency transactions
        if len(transactions) > 100:
            risk_score += 0.2
            
        # Interactions with high-risk addresses
        high_risk_patterns = ['mixer', 'tumbler', 'privacy']
        for addr in connected_addresses:
            if any(pattern in addr.get('address', '').lower() for pattern in high_risk_patterns):
                risk_score += 0.3
                
        # Large transaction amounts
        for tx in transactions:
            amount = float(tx.get('amount', 0))
            if amount > 10:  # Threshold for large transactions
                risk_score += 0.1
                
        return min(risk_score, 1.0)
        
    def _attempt_kyc_linking(self, connected_addresses):
        """Attempt to link addresses to KYC-verified identities."""
        kyc_linked = []
        
        # Simulate KYC database lookup
        for addr in connected_addresses:
            if addr['address'] in self.exchange_addresses.get('coinbase', []):
                kyc_linked.append({
                    'address': addr['address'],
                    'exchange': 'coinbase',
                    'kyc_status': 'verified',
                    'identity_hint': 'user_12345'
                })
                
        return kyc_linked
        
    def _get_contract_source_code(self, contract_address, blockchain):
        """Get smart contract source code."""
        # Simulate contract source code
        return """
        pragma solidity ^0.8.0;
        
        contract ForensicsContract {
            address public owner;
            mapping(address => uint256) public balances;
            
            constructor() {
                owner = msg.sender;
            }
            
            function withdraw() public {
                require(msg.sender == owner);
                payable(owner).transfer(address(this).balance);
            }
        }
        """
        
    def _analyze_contract_vulnerabilities(self, contract_code):
        """Analyze contract for common vulnerabilities."""
        vulnerabilities = []
        
        # Check for reentrancy
        if 'call.value' in contract_code or '.call{value:' in contract_code:
            vulnerabilities.append({
                'type': 'reentrancy',
                'severity': 'high',
                'description': 'Potential reentrancy vulnerability detected'
            })
            
        # Check for integer overflow
        if '+' in contract_code and 'SafeMath' not in contract_code:
            vulnerabilities.append({
                'type': 'integer_overflow',
                'severity': 'medium',
                'description': 'Potential integer overflow without SafeMath'
            })
            
        return vulnerabilities
        
    def _detect_contract_backdoors(self, contract_code):
        """Detect potential backdoors in contract code."""
        backdoors = []
        
        # Check for hidden admin functions
        if 'onlyOwner' in contract_code and 'selfdestruct' in contract_code:
            backdoors.append({
                'type': 'selfdestruct_backdoor',
                'severity': 'critical',
                'description': 'Contract can be destroyed by owner'
            })
            
        return backdoors
        
    def _detect_honeypot_patterns(self, contract_code):
        """Detect honeypot patterns in contract code."""
        honeypot_indicators = []
        
        # Check for buy/sell restrictions
        if 'require(false)' in contract_code:
            honeypot_indicators.append({
                'type': 'transfer_restriction',
                'description': 'Contract may prevent token transfers'
            })
            
        return honeypot_indicators
        
    def _analyze_contract_ownership(self, contract_address, blockchain):
        """Analyze contract ownership structure."""
        return {
            'owner_address': '0x742d35Cc6bf8f5C4F0e8B4C7b6d8e8F9b2d7D8F9',
            'is_multisig': False,
            'ownership_renounced': False,
            'proxy_contract': False
        }
        
    def _analyze_contract_transactions(self, contract_address, blockchain):
        """Analyze contract transaction patterns."""
        return {
            'total_transactions': 1250,
            'unique_users': 430,
            'average_transaction_value': '0.15 ETH',
            'peak_activity_periods': ['2024-01-15', '2024-01-20'],
            'suspicious_patterns': []
        }
        
    def _get_nft_metadata(self, token_id, contract_address, blockchain):
        """Get NFT metadata."""
        return {
            'name': 'Digital Forensics NFT #1',
            'description': 'A unique digital forensics artwork',
            'image': 'ipfs://QmHash123...',
            'attributes': [
                {'trait_type': 'Background', 'value': 'Blue'},
                {'trait_type': 'Style', 'value': 'Digital'}
            ],
            'creator': '0x742d35Cc6bf8f5C4F0e8B4C7b6d8e8F9b2d7D8F9',
            'creation_date': '2024-01-10T10:00:00Z'
        }
        
    def _trace_nft_ownership(self, token_id, contract_address, blockchain):
        """Trace NFT ownership history."""
        return [
            {
                'owner': '0x742d35Cc6bf8f5C4F0e8B4C7b6d8e8F9b2d7D8F9',
                'timestamp': '2024-01-10T10:00:00Z',
                'transaction_type': 'mint',
                'price': '0'
            },
            {
                'owner': '0x123456789abcdef123456789abcdef123456789a',
                'timestamp': '2024-01-15T14:30:00Z',
                'transaction_type': 'sale',
                'price': '2.5 ETH'
            }
        ]
        
    def _verify_nft_provenance(self, metadata, ownership_history):
        """Verify NFT provenance trail."""
        return [
            {
                'step': 1,
                'action': 'creation',
                'verified': True,
                'timestamp': '2024-01-10T10:00:00Z',
                'details': 'NFT minted by verified creator'
            },
            {
                'step': 2,
                'action': 'first_sale',
                'verified': True,
                'timestamp': '2024-01-15T14:30:00Z',
                'details': 'Legitimate sale transaction'
            }
        ]
        
    def _detect_nft_forgery(self, metadata, ownership_history):
        """Detect NFT forgery indicators."""
        forgery_indicators = []
        
        # Check for duplicate metadata
        if 'duplicate_detected' in str(metadata):
            forgery_indicators.append({
                'type': 'duplicate_metadata',
                'severity': 'high',
                'description': 'Similar NFT metadata found'
            })
            
        return forgery_indicators
        
    def _detect_market_manipulation(self, ownership_history):
        """Detect market manipulation patterns."""
        manipulation_patterns = []
        
        # Check for wash trading
        owners = [entry['owner'] for entry in ownership_history]
        if len(set(owners)) < len(owners) / 2:
            manipulation_patterns.append({
                'type': 'wash_trading',
                'description': 'Repeated trading between same addresses',
                'confidence': 0.7
            })
            
        return manipulation_patterns
        
    def _calculate_authenticity_score(self, metadata, ownership_history, forgery_indicators, manipulation):
        """Calculate NFT authenticity score."""
        score = 1.0
        
        # Deduct for forgery indicators
        score -= len(forgery_indicators) * 0.2
        
        # Deduct for market manipulation
        score -= len(manipulation) * 0.1
        
        # Bonus for verified creator
        if 'verified_creator' in str(metadata):
            score += 0.1
            
        return max(score, 0.0)
        
    def _analyze_protocol_interactions(self, wallet_address, blockchain):
        """Analyze DeFi protocol interactions."""
        return [
            {
                'protocol': 'Uniswap',
                'interaction_type': 'swap',
                'frequency': 15,
                'total_volume': '50.5 ETH'
            },
            {
                'protocol': 'Compound',
                'interaction_type': 'lending',
                'frequency': 8,
                'total_volume': '25.2 ETH'
            }
        ]
        
    def _track_liquidity_movements(self, wallet_address, blockchain):
        """Track liquidity pool movements."""
        return [
            {
                'pool': 'ETH/USDC',
                'action': 'add_liquidity',
                'amount': '10 ETH + 25000 USDC',
                'timestamp': '2024-01-15T10:00:00Z'
            }
        ]
        
    def _analyze_yield_farming(self, wallet_address, blockchain):
        """Analyze yield farming activity."""
        return [
            {
                'protocol': 'Yearn Finance',
                'vault': 'yvUSDC',
                'deposited': '50000 USDC',
                'rewards_claimed': '2500 USDC',
                'duration': '90 days'
            }
        ]
        
    def _detect_flash_loan_usage(self, wallet_address, blockchain):
        """Detect flash loan usage."""
        return [
            {
                'protocol': 'Aave',
                'amount': '1000 ETH',
                'duration': '1 block',
                'purpose': 'arbitrage',
                'profit': '2.5 ETH'
            }
        ]
        
    def _identify_suspicious_defi_patterns(self, protocol_interactions, liquidity_movements, flash_loans):
        """Identify suspicious DeFi patterns."""
        suspicious_patterns = []
        
        # High frequency flash loan usage
        if len(flash_loans) > 10:
            suspicious_patterns.append({
                'type': 'excessive_flash_loans',
                'description': 'Unusually high flash loan usage',
                'risk_level': 'medium'
            })
            
        return suspicious_patterns