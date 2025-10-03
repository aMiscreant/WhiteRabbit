# main.py
import argparse
import os
from scrub.exif_cleaner import remove_exif
from scrub.timestamp_reset import reset_timestamps
from secure_delete.shredder import shred_file

# Relay imports
from relay.relay_client import RelayClient
from relay.relay_server import RelayServer

def main():
    print("🐇 WhiteRabbit secure file tool invoked.")
    parser = argparse.ArgumentParser(description="WhiteRabbit CLI: Secure file laundering & obfuscation.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # remove-exif
    remove_parser = subparsers.add_parser('remove-exif', help='Remove EXIF metadata from image')
    remove_parser.add_argument('input', help='Input image file')
    remove_parser.add_argument('output', help='Output image file')

    # reset-timestamps
    timestamp_parser = subparsers.add_parser('reset-timestamps', help='Reset file timestamps')
    timestamp_parser.add_argument('file', help='File to reset timestamps on')

    # shred
    shred_parser = subparsers.add_parser('shred', help='Securely delete file by overwriting')
    shred_parser.add_argument('file', help='File to shred')
    shred_parser.add_argument('--passes', type=int, default=3, help='Number of overwrite passes')

    # start-relay
    start_parser = subparsers.add_parser('start-relay', help='Start a relay server (dev only)')
    start_parser.add_argument('--host', default='127.0.0.1', help='Bind host')
    start_parser.add_argument('--port', type=int, default=5000, help='Bind port')
    start_parser.add_argument('--hop-index', type=int, required=True, help='Hop index (0-based)')
    start_parser.add_argument('--total-hops', type=int, required=True, help='Total hops in chain')
    start_parser.add_argument('--next-hop', help='Next hop URL (omit for final hop)')

    # send file via relays
    send_parser = subparsers.add_parser('send', help='Send file through relay chain')
    send_parser.add_argument('file', help='File to send')
    send_parser.add_argument('--hops', required=True, help='Comma-separated list of hop base URLs, first hop first')
    send_parser.add_argument('--master-secret', help='Master secret to derive per-hop keys (optional, can use env var)')

    # receive file
    recv_parser = subparsers.add_parser('receive', help='Receive file from final hop by file_id')
    recv_parser.add_argument('file_id', help='File ID returned by final hop')
    recv_parser.add_argument('output', help='Output path to write file')
    recv_parser.add_argument('--hops', required=True, help='Comma-separated list of hop base URLs, first hop first')
    recv_parser.add_argument('--master-secret', help='Master secret to derive per-hop keys (optional)')

    args = parser.parse_args()

    if args.command == 'remove-exif':
        remove_exif(args.input, args.output)
        print(f"EXIF data removed and saved to {args.output}")
    elif args.command == 'reset-timestamps':
        reset_timestamps(args.file)
        print(f"Timestamps reset on {args.file}")
    elif args.command == 'shred':
        shred_file(args.file, args.passes)
        print(f"File {args.file} shredded with {args.passes} passes.")
    elif args.command == 'start-relay':
        server = RelayServer(address=args.host, port=args.port,
                             hop_index=args.hop_index, total_hops=args.total_hops,
                             next_hop_url=args.next_hop)
        # helpful for import-based instantiation
        from relay.relay_server import relay_server_instance
        relay_server_instance = server
        server.start()
        print(f"Relay server running on {args.host}:{args.port}. Press Ctrl-C to exit.")
        try:
            # keep main thread alive while Flask runs in background
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down (dev server).")
    elif args.command == 'send':
        hops = [h.strip() for h in args.hops.split(",") if h.strip()]
        client = RelayClient(hops, master_secret=args.master_secret)
        ok = client.send_file(args.file)
        print("Send OK" if ok else "Send failed.")
    elif args.command == 'receive':
        hops = [h.strip() for h in args.hops.split(",") if h.strip()]
        client = RelayClient(hops, master_secret=args.master_secret)
        ok = client.receive_file(args.file_id, args.output)
        print("Receive OK" if ok else "Receive failed.")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
