import sys
import uvicorn
from netvibe.fastapi_app import app

def main():
    """Main entry point for the netvibe CLI."""
    print("--------------------------------------------------")
    print("   NETVIBE | AI Traffic Monitoring Intelligence   ")
    print("--------------------------------------------------")
    print("Dashboard: http://localhost:8503")
    print("Press Ctrl+C to stop.")
    print("--------------------------------------------------")
    
    try:
        # Run the FastAPI server
        uvicorn.run(app, host="0.0.0.0", port=8503, log_level="info")  # nosec B104
    except KeyboardInterrupt:
        print("\n[NetVibe] Shutdown requested by user.")
    except Exception as e:
        print(f"\n[NetVibe] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
