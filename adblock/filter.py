"""
Main ad filter
"""
import os
from adblock import load_blocklist, DNSSinkholeServer


def main():
    HOST = '127.0.0.1' # localhost for now. will change to monitor whatever ip we might use
    PORT = 5353
    UPSTREAM_DNS = '8.8.8.8'  # Google DNS


    # load blocklist from parent directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    blocklist_path = os.path.join(os.path.dirname(script_dir), 'blocklist.txt')

    print("Starting AdBlocker")

    try:
        blocklist = load_blocklist(blocklist_path)
    except FileNotFoundError:
        return
    except:
        return

    sinkhole = DNSSinkholeServer(
        blocklist=blocklist,
        host=HOST,
        port=PORT,
        upstream_dns=UPSTREAM_DNS
    )

    try:
        sinkhole.start()
    except KeyboardInterrupt: # ctrl+c
        sinkhole.stop()
    except:
        sinkhole.stop()

if __name__ == "__main__":
    main()