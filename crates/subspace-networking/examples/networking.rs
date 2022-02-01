use libp2p::futures::channel::mpsc;
use libp2p::futures::StreamExt;
use libp2p::identity::ed25519::Keypair;
use std::sync::Arc;
use std::time::Duration;
use subspace_networking::{Config, Node};

#[tokio::main]
async fn main() {
    let mut config_1 = Config::new(Keypair::generate());
    config_1
        .listen_on
        .push("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    let (node_1, mut node_runner_1) = Node::create(config_1).await.unwrap();

    let (node_1_addresses_sender, mut node_1_addresses_receiver) = mpsc::unbounded();
    node_1
        .on_new_listener(Arc::new(move |address| {
            node_1_addresses_sender
                .unbounded_send(address.clone())
                .unwrap();
        }))
        .detach();

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    let mut config_2 = Config::new(Keypair::generate());
    config_2
        .listen_on
        .push("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    config_2
        .bootstrap_nodes
        .push((node_1.id(), node_1_addresses_receiver.next().await.unwrap()));

    let (node_2, mut node_runner_2) = Node::create(config_2).await.unwrap();

    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
}
