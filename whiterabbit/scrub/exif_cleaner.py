from PIL import Image
import piexif

def remove_exif(input_path: str, output_path: str) -> str:
    """
    Remove all EXIF metadata from an image file without modifying the original file.

    Args:
        input_path (str): Path to the source image.
        output_path (str): Path to save the cleaned image.

    Returns:
        str: Path to the cleaned image file.
    """
    try:
        with Image.open(input_path) as img:
            if input_path.lower().endswith(('.jpg', '.jpeg')):
                # Load and strip EXIF safely
                exif_dict = piexif.load(img.info.get("exif", b""))
                exif_dict["0th"] = {}
                exif_dict["Exif"] = {}
                exif_dict["GPS"] = {}
                exif_dict["Interop"] = {}
                exif_dict["1st"] = {}
                exif_dict["thumbnail"] = None

                exif_bytes = piexif.dump(exif_dict)
                img.save(output_path, "jpeg", exif=exif_bytes)
            else:
                # Just save clean copy for non-JPEGs
                img.save(output_path)
        return output_path
    except Exception as e:
        raise RuntimeError(f"Failed to remove EXIF: {e}")
