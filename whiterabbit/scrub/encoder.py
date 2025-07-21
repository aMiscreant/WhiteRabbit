from PIL import Image

def reencode_image(input_path: str, output_path: str, quality: int = 85) -> str:
    """
    Re-encode an image to normalize compression artifacts.

    Args:
        input_path (str): Path to the source image.
        output_path (str): Path to save the re-encoded image.
        quality (int): JPEG quality (1-100).

    Returns:
        str: Path to the re-encoded image.
    """
    try:
        with Image.open(input_path) as img:
            # Convert to RGB if necessary (JPEG doesn't support transparency)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            img.save(output_path, format="JPEG", quality=quality, optimize=True)
    except Exception as e:
        raise RuntimeError(f"Failed to re-encode image: {e}")

    return output_path
