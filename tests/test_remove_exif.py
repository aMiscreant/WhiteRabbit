import os
import tempfile
from whiterabbit.scrub.exif_cleaner import remove_exif

def test_remove_exif():
    input_image = "sample_with_exif.jpg"  # Add a test image with EXIF here
    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
        output_image = tmp.name

    # Run the function (you'll implement it)
    remove_exif(input_image, output_image)

    # Check output file exists
    assert os.path.exists(output_image)

    # TODO: Add actual checks to verify EXIF removed

    os.remove(output_image)
