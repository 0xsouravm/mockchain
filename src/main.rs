use chrono::{DateTime, Utc};
use secp256k1::{PublicKey, Secp256k1};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use log::{info, warn};

pub mod blockchain {
    tonic::include_proto!("blockchain");
}

const FAUCET_MOCKCHAIN_ADDRESS: &str = "FAUCET_MOCKCHAIN_ADDRESS";

use blockchain::blockchain_service_server::{BlockchainService, BlockchainServiceServer};
use blockchain::{
    Transaction as ProtoTransaction,
    TransactionResponse,
    BalanceRequest,
    BalanceResponse,
    FaucetRequest,
    FaucetResponse,
};

// Consensus trait defines how blocks are produced and validated
pub trait Consensus: Send + Sync {
    fn generate_block(&self, index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Block;
    fn validate_block(&self, block: &Block, previous_hash: &str) -> bool;
    fn start(&self, blockchain: Arc<Mutex<Blockchain>>);
    fn name(&self) -> &str;
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
    server.blockchain.lock().await.consensus.start(Arc::clone(&server.blockchain));
    
    let addr = "[::1]:50051".parse()?;
    info!("Starting gRPC server on {}", addr);
    
    Server::builder()
        .add_service(BlockchainServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}