use bp_sdk::*;
use std::time::Duration;
use tokio_test;

#[tokio::test]
async fn test_sdk_lifecycle() {
    let node_eid = Eid::new("ipn:1.1").unwrap();
    let sdk = BpSdk::new(node_eid, None).unwrap();

    // Should not be initialized initially
    assert!(!sdk.is_initialized());

    // Initialize
    sdk.init().await.unwrap();
    assert!(sdk.is_initialized());

    // Should be able to create endpoints
    let endpoint_eid = Eid::new("ipn:1.1").unwrap();
    let endpoint = sdk.create_endpoint(endpoint_eid.clone()).await.unwrap();
    assert_eq!(endpoint.eid(), &endpoint_eid);

    // Should be able to get the endpoint
    let retrieved = sdk.get_endpoint(&endpoint_eid);
    assert!(retrieved.is_some());

    // Should be able to remove endpoint
    sdk.remove_endpoint(&endpoint_eid).await.unwrap();
    let retrieved = sdk.get_endpoint(&endpoint_eid);
    assert!(retrieved.is_none());

    // Shutdown
    sdk.shutdown().await.unwrap();
    assert!(!sdk.is_initialized());
}

#[tokio::test]
async fn test_endpoint_lifecycle() {
    let node_eid = Eid::new("ipn:1.1").unwrap();
    let sdk = BpSdk::new(node_eid, None).unwrap();
    sdk.init().await.unwrap();

    let endpoint_eid = Eid::new("ipn:1.1").unwrap();
    let endpoint = sdk.create_endpoint(endpoint_eid.clone()).await.unwrap();

    // Test endpoint properties
    assert_eq!(endpoint.eid(), &endpoint_eid);

    // Test duplicate creation should fail
    let result = sdk.create_endpoint(endpoint_eid).await;
    assert!(matches!(result, Err(BpError::Duplicate)));

    sdk.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_bundle_creation_and_validation() {
    let source = Eid::new("ipn:1.1").unwrap();
    let dest = Eid::new("ipn:2.1").unwrap();
    let report_to = Eid::new("ipn:3.1").unwrap();

    let bundle = Bundle::new(source.clone(), dest.clone(), "Hello, DTN!")
        .with_priority(Priority::Expedited)
        .with_custody(Custody::Required)
        .with_ttl(Duration::from_secs(7200))
        .with_report_to(report_to.clone())
        .add_metadata("test", "value");

    assert_eq!(bundle.source_eid, source);
    assert_eq!(bundle.dest_eid, dest);
    assert_eq!(bundle.report_to_eid, Some(report_to));
    assert_eq!(bundle.priority, Priority::Expedited);
    assert_eq!(bundle.custody, Custody::Required);
    assert_eq!(bundle.ttl, Duration::from_secs(7200));
    assert_eq!(bundle.payload, "Hello, DTN!".as_bytes());
    assert_eq!(bundle.metadata.get("test"), Some(&"value".to_string()));
    assert!(!bundle.is_expired());
}

#[tokio::test]
async fn test_cla_manager_operations() {
    let manager = ClaManager::new();

    // Should start empty
    assert!(manager.list_protocols().is_empty());

    // Create and register UDP CLA
    let udp_cla = manager.create_udp_cla("127.0.0.1:0").await.unwrap();
    
    // Should have UDP protocol now
    let protocols = manager.list_protocols();
    assert_eq!(protocols.len(), 1);
    assert!(protocols.contains(&"udp".to_string()));

    // Should be able to get the CLA
    let retrieved = manager.get("udp");
    assert!(retrieved.is_some());

    // Test CLA properties
    assert_eq!(udp_cla.protocol(), "udp");
    assert!(udp_cla.local_address().starts_with("127.0.0.1:"));
    assert_eq!(udp_cla.max_payload_size(), 1472);

    // Create and register TCP CLA
    let tcp_cla = manager.create_tcp_cla("127.0.0.1:0").await.unwrap();
    
    // Should have both protocols now
    let protocols = manager.list_protocols();
    assert_eq!(protocols.len(), 2);
    assert!(protocols.contains(&"udp".to_string()));
    assert!(protocols.contains(&"tcp".to_string()));

    // Test TCP CLA properties
    assert_eq!(tcp_cla.protocol(), "tcp");
    assert!(tcp_cla.local_address().starts_with("127.0.0.1:"));
    assert_eq!(tcp_cla.max_payload_size(), 65536);

    // Unregister CLAs
    manager.unregister("udp").unwrap();
    manager.unregister("tcp").unwrap();
    assert!(manager.list_protocols().is_empty());
}

#[tokio::test]
async fn test_error_handling() {
    // Test invalid EID
    let result = Eid::new("invalid_eid");
    assert!(matches!(result, Err(BpError::InvalidArgs)));

    // Test operations on uninitialized SDK
    let node_eid = Eid::new("ipn:1.1").unwrap();
    let sdk = BpSdk::new(node_eid, None).unwrap();

    let endpoint_eid = Eid::new("ipn:1.1").unwrap();
    let result = sdk.create_endpoint(endpoint_eid).await;
    assert!(matches!(result, Err(BpError::NotInitialized)));

    // Test CLA manager errors
    let manager = ClaManager::new();
    let result = manager.get("nonexistent");
    assert!(result.is_none());

    let result = manager.unregister("nonexistent");
    assert!(matches!(result, Err(BpError::NotFound)));
}

#[tokio::test]
async fn test_statistics() {
    let node_eid = Eid::new("ipn:1.1").unwrap();
    let sdk = BpSdk::new(node_eid, None).unwrap();

    // Initial statistics should be zero
    let stats = sdk.statistics();
    assert_eq!(stats.bundles_sent, 0);
    assert_eq!(stats.bytes_sent, 0);

    // Reset should work
    sdk.reset_statistics();
    let stats = sdk.statistics();
    assert_eq!(stats.bundles_sent, 0);
}

#[tokio::test]
async fn test_route_management() {
    let dest = Eid::new("ipn:2.1").unwrap();
    let next_hop = Eid::new("ipn:3.1").unwrap();

    let route = Route::new(dest.clone(), next_hop.clone(), 100)
        .with_confidence(0.8)
        .with_validity(chrono::Utc::now() + chrono::Duration::hours(1));

    assert_eq!(route.dest_eid, dest);
    assert_eq!(route.next_hop, next_hop);
    assert_eq!(route.cost, 100);
    assert_eq!(route.confidence, 0.8);
    assert!(route.is_valid());

    // Test confidence clamping
    let route2 = Route::new(dest, next_hop, 200)
        .with_confidence(1.5); // Should be clamped to 1.0
    assert_eq!(route2.confidence, 1.0);
}

#[tokio::test]
async fn test_contact_management() {
    let neighbor = Eid::new("ipn:2.1").unwrap();
    let start = chrono::Utc::now();
    let end = start + chrono::Duration::hours(2);

    let contact = Contact::new(neighbor.clone(), start, end, 1_000_000);

    assert_eq!(contact.neighbor_eid, neighbor);
    assert_eq!(contact.start_time, start);
    assert_eq!(contact.end_time, end);
    assert_eq!(contact.data_rate, 1_000_000);
    assert_eq!(contact.duration(), chrono::Duration::hours(2));
    // Contact might not be active if start time is in future
}

#[tokio::test]
async fn test_range_management() {
    let neighbor = Eid::new("ipn:2.1").unwrap();
    let start = chrono::Utc::now();
    let end = start + chrono::Duration::hours(1);
    let owlt = Duration::from_secs(5);

    let range = Range::new(neighbor.clone(), start, end, owlt);

    assert_eq!(range.neighbor_eid, neighbor);
    assert_eq!(range.start_time, start);
    assert_eq!(range.end_time, end);
    assert_eq!(range.owlt, owlt);
    // Range might not be valid if start time is in future
}

#[test]
fn test_transport_config_creation() {
    let tcp_config = TransportConfig::tcp("192.168.1.100:8080");
    assert_eq!(tcp_config.protocol, "tcp");
    assert_eq!(tcp_config.local_address, "192.168.1.100:8080");
    assert_eq!(tcp_config.max_payload_size, 65536);
    assert_eq!(tcp_config.data_rate, 1_000_000);

    let udp_config = TransportConfig::udp("10.0.0.1:9090");
    assert_eq!(udp_config.protocol, "udp");
    assert_eq!(udp_config.local_address, "10.0.0.1:9090");
    assert_eq!(udp_config.max_payload_size, 1472);
    assert_eq!(udp_config.data_rate, 1_000_000);
}

#[test]
fn test_timestamp_operations() {
    let timestamp = BpTimestamp::now();
    assert!(timestamp.msec > 0);

    let datetime = timestamp.to_datetime();
    assert!(datetime.timestamp() > 0);
}

#[test]
fn test_eid_operations() {
    let eid = Eid::new("ipn:123.456").unwrap();
    
    assert_eq!(eid.node_number(), Some(123));
    assert_eq!(eid.service_number(), Some(456));
    assert_eq!(eid.as_str(), "ipn:123.456");
    assert_eq!(eid.to_string(), "ipn:123.456");

    // Test parsing from string
    let parsed: Eid = "ipn:789.012".parse().unwrap();
    assert_eq!(parsed.node_number(), Some(789));
    assert_eq!(parsed.service_number(), Some(12));
}

#[test]
fn test_bundle_expiration() {
    let source = Eid::new("ipn:1.1").unwrap();
    let dest = Eid::new("ipn:2.1").unwrap();

    // Create bundle with very short TTL
    let bundle = Bundle::new(source, dest, "test")
        .with_ttl(Duration::from_millis(1));

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(10));
    assert!(bundle.is_expired());

    // Create bundle with long TTL
    let source = Eid::new("ipn:1.1").unwrap();
    let dest = Eid::new("ipn:2.1").unwrap();
    let bundle = Bundle::new(source, dest, "test")
        .with_ttl(Duration::from_secs(3600));
    assert!(!bundle.is_expired());
} 