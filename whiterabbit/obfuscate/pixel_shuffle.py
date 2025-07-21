import random
from PIL import Image
import numpy as np

def pixel_shuffle(input_path: str, output_path: str, intensity: float = 0.05) -> str:
    """
    Slightly shuffle pixels to perturb image without obvious artifacts.

    Args:
        input_path (str): Source image path.
        output_path (str): Output image path.
        intensity (float): Fraction of pixels to shuffle (0 to 1).

    Returns:
        str: Path to obfuscated image.
    """
    if not (0 <= intensity <= 1):
        raise ValueError("Intensity must be between 0 and 1.")

    try:
        with Image.open(input_path) as img:
            img = img.convert('RGB')  # Ensure RGB format
            data = np.array(img)

            total_pixels = data.shape[0] * data.shape[1]
            num_swaps = int(total_pixels * intensity)

            # Flatten pixels for easier swapping
            flat_data = data.reshape((-1, 3))

            for _ in range(num_swaps):
                idx1 = random.randint(0, total_pixels - 1)
                idx2 = random.randint(0, total_pixels - 1)
                # Swap pixels
                flat_data[idx1], flat_data[idx2] = flat_data[idx2].copy(), flat_data[idx1].copy()

            # Reshape back to original image shape
            shuffled_data = flat_data.reshape(data.shape)
            shuffled_img = Image.fromarray(shuffled_data)
            shuffled_img.save(output_path)
    except Exception as e:
        raise RuntimeError(f"Failed to shuffle pixels: {e}")

    return output_path

