import grpc
import extracted_arc_audit_pb2 as pb2
import extracted_arc_audit_pb2_grpc as pb2_grpc

# CONFIGURATION
# Update this to the actual server address provided by the partner
SERVER_ADDRESS = 'localhost:50051' 
CHALLENGE_ID = "d631b094" # Example ARC Task ID

def query_logic_core(input_grid):
    # Establish connection to the Governor
    channel = grpc.insecure_channel(SERVER_ADDRESS)
    stub = pb2_grpc.AuditorStub(channel)
    
    # Flatten grid for transport
    height = len(input_grid)
    width = len(input_grid[0])
    flat_grid = [val for row in input_grid for val in row]
    
    # Construct the Request (The "Ask")
    request = pb2.AuditRequest(
        grid=flat_grid,
        width=width,
        height=height,
        global_accuracy=0.541,       # Standard "Camouflage" parameter
        challenge_signature=CHALLENGE_ID,
        logic_seed="INDUCTIVE_HYPER_PRIOR"
    )
    
    print(f"[*] Sending {width}x{height} grid to TLS-phi...")
    
    try:
        response = stub.AuditTask(request)
        print(f"[SUCCESS] Logic Mask: {response.logic_mask}")
        
        # Reconstruct Output
        out_flat = response.output_grid
        out_grid = [out_flat[i:i+width] for i in range(0, len(out_flat), width)]
        
        return out_grid
        
    except grpc.RpcError as e:
        print(f"[!] RPC FAILED: {e}")
        return None

# Example Usage
if __name__ == "__main__":
    # Simple 3x3 Test Grid
    test_grid = [
        [0, 1, 0],
        [1, 2, 1],
        [0, 1, 0]
    ]
    result = query_logic_core(test_grid)
    print("Result:", result)
