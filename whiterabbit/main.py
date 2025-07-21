import argparse
from whiterabbit.scrub.exif_cleaner import remove_exif
from whiterabbit.scrub.timestamp_reset import reset_timestamps
from whiterabbit.secure_delete.shredder import shred_file

def main():
    print("🐇 WhiteRabbit secure file tool invoked.")
    parser = argparse.ArgumentParser(description="WhiteRabbit CLI: Secure file laundering & obfuscation.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Example: remove-exif command
    remove_parser = subparsers.add_parser('remove-exif', help='Remove EXIF metadata from image')
    remove_parser.add_argument('input', help='Input image file')
    remove_parser.add_argument('output', help='Output image file')

    # Example: reset-timestamps command
    timestamp_parser = subparsers.add_parser('reset-timestamps', help='Reset file timestamps')
    timestamp_parser.add_argument('file', help='File to reset timestamps on')

    # Example: shred command
    shred_parser = subparsers.add_parser('shred', help='Securely delete file by overwriting')
    shred_parser.add_argument('file', help='File to shred')
    shred_parser.add_argument('--passes', type=int, default=3, help='Number of overwrite passes')

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

if __name__ == '__main__':
    main()
