use chrono::{DateTime, Utc};
use log::{info, warn};
use secp256k1::{PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

pub mod blockchain {
    tonic::include_proto!("blockchain");
}

const FAUCET_MOCKCHAIN_ADDRESS: &str = "FAUCET_MOCKCHAIN_ADDRESS";

use blockchain::blockchain_service_server::{BlockchainService, BlockchainServiceServer};
use blockchain::{
    BalanceRequest, BalanceResponse, FaucetRequest, FaucetResponse, HistoryRequest,
    HistoryResponse, StateResponse, Transaction as ProtoTransaction, TransactionResponse,
};

// Consensus trait defines how blocks are produced and validated
pub trait Consensus: Send + Sync {
    fn generate_block(
        &self,
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
    ) -> Block;
    fn validate_block(&self, block: &Block, previous_hash: &str) -> bool;
    fn start(&self, blockchain: Arc<Mutex<Blockchain>>);
    fn name(&self) -> &str;
}

// Available consensus types
#[derive(Debug)]
pub enum ConsensusType {
    ProofOfWorkType { difficulty: usize },
    ProofOfStakeType { min_stake: u64 },
}

impl ConsensusType {
    fn create_consensus(&self) -> Box<dyn Consensus> {
        match self {
            ConsensusType::ProofOfWorkType { difficulty } => {
                Box::new(ProofOfWork::new(*difficulty))
            }
            ConsensusType::ProofOfStakeType { min_stake: _ } => todo!(),
        }
    }
}

// Proof of Work implementation
pub struct ProofOfWork {
    difficulty: usize,
}

impl ProofOfWork {
    pub fn new(difficulty: usize) -> Self {
        Self { difficulty }
    }
}

impl Consensus for ProofOfWork {
    fn name(&self) -> &str {
        "Proof of Work"
    }

    fn generate_block(
        &self,
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
    ) -> Block {
        let mut block = Block::new(index, transactions, previous_hash);

        let target = "0".repeat(self.difficulty);
        while !block.hash.starts_with(&target) {
            block.nonce += 1;
            block.hash = block.calculate_hash();
        }

        block
    }

    fn validate_block(&self, block: &Block, previous_hash: &str) -> bool {
        if block.previous_hash != previous_hash {
            return false;
        }

        if block.hash != block.calculate_hash() {
            return false;
        }

        block.hash.starts_with(&"0".repeat(self.difficulty))
    }

    fn start(&self, blockchain: Arc<Mutex<Blockchain>>) {
        tokio::spawn(async move {
            let secp = Secp256k1::new();
            let (_, miner_key) = secp.generate_keypair(&mut rand::thread_rng());
            info!(
                "PoW mining with address: {}",
                hex::encode(miner_key.serialize())
            );

            loop {
                {
                    let mut chain = blockchain.lock().await;
                    if chain.transaction_pool.len() > 10 {
                        if let Some(block) = chain.mine_pending_transactions(&miner_key) {
                            info!("Mined block {} with hash {}", block.index, block.hash);
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
    }
}

pub struct ProofOfStake {
    min_stake: u64,
}

impl Consensus for ProofOfStake {
    fn name(&self) -> &str {
        "Proof of Stake"
    }

    fn generate_block(
        &self,
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
    ) -> Block {
    }

    fn validate_block(&self, block: &Block, previous_hash: &str) -> bool {}

    fn start(&self, blockchain: Arc<Mutex<Blockchain>>) {
        tokio::spawn(async move {
            let secp = Secp256k1::new();
            let (_, miner_key) = secp.generate_keypair(&mut rand::thread_rng());
            info!(
                "PoS mining with address: {}",
                hex::encode(miner_key.serialize())
            );

            loop {
                {
                    let mut chain = blockchain.lock().await;
                    if chain.transaction_pool.len() > 10 {
                        if let Some(block) = chain.mine_pending_transactions(&miner_key) {
                            info!("Mined block {} with hash {}", block.index, block.hash);
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn new(from: &str, to: &str, amount: u64) -> Self {
        Self {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            signature: Vec::new(),
        }
    }

    pub fn get_message_to_sign(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_string(&(&self.from, &self.to, self.amount, self.timestamp))
                .unwrap()
                .as_bytes(),
        );
        hasher.finalize().to_vec()
    }

    pub fn verify(&self) -> bool {
        // Skip verification for faucet transactions
        if self.from == FAUCET_MOCKCHAIN_ADDRESS {
            return true;
        }

        let secp = Secp256k1::new();

        let public_key_bytes = match hex::decode(&self.from) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to decode public key: {}", e);
                return false;
            }
        };

        let public_key = match PublicKey::from_slice(&public_key_bytes) {
            Ok(key) => key,
            Err(e) => {
                warn!("Invalid public key: {}", e);
                return false;
            }
        };

        if let Ok(sig) = secp256k1::ecdsa::Signature::from_compact(&self.signature) {
            let message = self.get_message_to_sign();
            if let Ok(msg) = secp256k1::Message::from_slice(&message) {
                return secp.verify_ecdsa(&msg, &sig, &public_key).is_ok();
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
    pub miner: String,
}

impl Block {
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let mut block = Self {
            index,
            timestamp: Utc::now(),
            transactions,
            previous_hash,
            hash: String::new(),
            nonce: 0,
            miner: String::new(),
        };
        block.hash = block.calculate_hash();
        block
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let content = serde_json::to_string(&(
            self.index,
            self.timestamp,
            &self.transactions,
            &self.previous_hash,
            self.nonce,
        ))
        .unwrap();

        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub transaction_pool: VecDeque<Transaction>,
    consensus: Box<dyn Consensus>,
}

impl Blockchain {
    pub fn new(consensus: Box<dyn Consensus>) -> Self {
        let genesis_block = consensus.generate_block(0, Vec::new(), String::from("0"));
        info!(
            "Creating new blockchain with {} consensus",
            consensus.name()
        );

        Self {
            chain: vec![genesis_block],
            transaction_pool: VecDeque::new(),
            consensus,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> bool {
        // Allow transactions from the faucet without verification
        if transaction.from == FAUCET_MOCKCHAIN_ADDRESS {
            info!(
                "Adding faucet transaction to pool: FAUCET -> {}, amount: {}",
                transaction.to, transaction.amount
            );
            self.transaction_pool.push_back(transaction);
            return true;
        }

        if !transaction.verify() {
            warn!("Transaction verification failed");
            return false;
        }

        if !self.check_balance(&transaction.from, transaction.amount) {
            warn!("Insufficient balance for transaction");
            return false;
        }

        info!(
            "Adding transaction to pool: {} -> {}, amount: {}",
            transaction.from, transaction.to, transaction.amount
        );
        self.transaction_pool.push_back(transaction);
        true
    }

    pub fn mine_pending_transactions(&mut self, miner_key: &PublicKey) -> Option<Block> {
        if self.transaction_pool.is_empty() {
            return None;
        }

        let transactions: Vec<Transaction> = self.transaction_pool.drain(..).collect();
        let previous_block = self.chain.last()?;

        let mut block = self.consensus.generate_block(
            previous_block.index + 1,
            transactions,
            previous_block.hash.clone(),
        );

        block.miner = hex::encode(miner_key.serialize());
        self.chain.push(block.clone());
        Some(block)
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        let mut balance = 0;
        for block in &self.chain {
            for tx in &block.transactions {
                if tx.to == address {
                    balance += tx.amount;
                }
                if tx.from == address {
                    balance = balance.saturating_sub(tx.amount);
                }
            }
            if block.miner == address {
                balance += 50; // Mining reward
            }
        }
        balance
    }

    pub fn check_balance(&self, address: &str, amount: u64) -> bool {
        let balance = self.get_balance(address);
        balance >= amount
    }

    pub fn get_state(&self) -> Vec<Block> {
        self.chain.clone()
    }

    pub fn get_history(&self, address: &str) -> Vec<Transaction> {
        let mut history: Vec<Transaction> = Vec::new();
        for block in &self.chain {
            for tx in &block.transactions {
                if tx.from == address || tx.to == address {
                    history.push(tx.clone());
                }
            }
        }
        history
    }

    pub fn get_block_from_index(&self, index: u64) -> Option<Block> {
        self.chain
            .iter()
            .find(|block| block.index == index)
            .cloned()
    }
}

pub struct BlockchainServer {
    blockchain: Arc<Mutex<Blockchain>>,
}

impl BlockchainServer {
    pub fn new(blockchain: Blockchain) -> Self {
        Self {
            blockchain: Arc::new(Mutex::new(blockchain)),
        }
    }
}

#[tonic::async_trait]
impl BlockchainService for BlockchainServer {
    async fn submit_transaction(
        &self,
        request: Request<ProtoTransaction>,
    ) -> Result<Response<TransactionResponse>, Status> {
        let tx = request.into_inner();

        let transaction = Transaction {
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            timestamp: tx.timestamp,
            signature: tx.signature,
        };

        let mut chain = self.blockchain.lock().await;
        let success = chain.add_transaction(transaction);

        Ok(Response::new(TransactionResponse {
            success,
            message: if success {
                "Transaction accepted".into()
            } else {
                "Transaction failed".into()
            },
        }))
    }

    async fn get_balance(
        &self,
        request: Request<BalanceRequest>,
    ) -> Result<Response<BalanceResponse>, Status> {
        let address = request.into_inner().address;
        let chain = self.blockchain.lock().await;
        let balance = chain.get_balance(&address);

        Ok(Response::new(BalanceResponse { balance }))
    }

    async fn request_faucet(
        &self,
        request: Request<FaucetRequest>,
    ) -> Result<Response<FaucetResponse>, Status> {
        let address = request.into_inner().address;
        info!("Faucet request for address: {}", address);

        // Create a faucet transaction
        let faucet_amount = 1000; // Amount for testing

        // Create a system transaction to fund the account
        let transaction = Transaction {
            from: FAUCET_MOCKCHAIN_ADDRESS.to_string(), // Special faucet address
            to: address.clone(),
            amount: faucet_amount,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            signature: vec![], // No signature needed for faucet
        };

        let mut chain = self.blockchain.lock().await;
        let success = chain.add_transaction(transaction);

        // Immediately try to mine a block with this transaction
        let secp = Secp256k1::new();
        let (_, faucet_key) = secp.generate_keypair(&mut rand::thread_rng());

        if let Some(block) = chain.mine_pending_transactions(&faucet_key) {
            info!("Created faucet block with hash {}", block.hash);

            Ok(Response::new(FaucetResponse {
                success: true,
                amount: faucet_amount,
                message: "Faucet funds sent successfully".to_string(),
            }))
        } else {
            Ok(Response::new(FaucetResponse {
                success,
                amount: if success { faucet_amount } else { 0 },
                message: if success {
                    "Faucet funds queued for next block".to_string()
                } else {
                    "Failed to process faucet request".to_string()
                },
            }))
        }
    }

    async fn get_history(
        &self,
        request: Request<HistoryRequest>,
    ) -> Result<Response<HistoryResponse>, Status> {
        let address = request.into_inner().address;
        let chain = self.blockchain.lock().await;
        let history = chain.get_history(&address);
        Ok(Response::new(HistoryResponse {
            transactions: history.into_iter().map(Into::into).collect(),
        }))
    }

    async fn get_state(&self) -> Result<Response<StateResponse>, Status> {
        let chain = self.blockchain.lock().await;
        let state = chain.get_state();
        Ok(Response::new(StateResponse {
            blocks: state.into_iter().map(Into::into).collect(),
        }))
    }

    async fn get_block(
        &self,
        request: Request<blockchain::GetBlockRequest>,
    ) -> Result<Response<blockchain::GetBlockResponse>, Status> {
        let index = request.into_inner().index;
        let chain = self.blockchain.lock().await;
        match chain.get_block_from_index(index) {
            Some(block) => Ok(Response::new(blockchain::GetBlockResponse {
                block: Some(block.into()),
            })),
            None => Err(Status::not_found("Block not found")),
        }
    }
}

// implements conversion of transactions to blockchain::Transaction
impl From<Transaction> for ProtoTransaction {
    fn from(tx: Transaction) -> Self {
        Self {
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            timestamp: tx.timestamp,
            signature: tx.signature,
        }
    }
}

// implements conversion of Block to blockchain::Block
impl From<Block> for blockchain::Block {
    fn from(block: Block) -> Self {
        Self {
            index: block.index,
            timestamp: block.timestamp.timestamp(),
            transactions: block.transactions.into_iter().map(Into::into).collect(),
            previous_hash: block.previous_hash,
            hash: block.hash,
            nonce: block.nonce,
            miner: block.miner,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    // Choose consensus mechanism (could come from args/config)
    let consensus_type = ConsensusType::ProofOfWorkType { difficulty: 3 };
    let consensus = consensus_type.create_consensus();

    info!("Blockchain node starting...");
    let blockchain = Blockchain::new(consensus);
    let server = BlockchainServer::new(blockchain);

    // Start consensus mechanism
    server
        .blockchain
        .lock()
        .await
        .consensus
        .start(Arc::clone(&server.blockchain));

    let addr = "[::1]:50051".parse()?;
    info!("Starting gRPC server on {}", addr);

    Server::builder()
        .add_service(BlockchainServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
