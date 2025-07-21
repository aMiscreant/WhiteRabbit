import numpy as np
from PIL import Image
import io

def add_noise(input_path: str, output_path: str, noise_level: float = 0.02, jpeg_quality: int = 85) -> str:
    """
    Inject Gaussian noise and optional JPEG compression artifacts to obfuscate image.

    Args:
        input_path (str): Source image path.
        output_path (str): Output image path.
        noise_level (float): Noise intensity (0 to 1, typical 0.01-0.05).
        jpeg_quality (int): JPEG quality (1-100), lower = more artifacts.

    Returns:
        str: Path to noisy image.
    """
    if not (0 <= noise_level <= 1):
        raise ValueError("Noise level must be between 0 and 1.")
    if not (1 <= jpeg_quality <= 100):
        raise ValueError("JPEG quality must be between 1 and 100.")

    try:
        with Image.open(input_path) as img:
            img = img.convert('RGB')
            data = np.array(img) / 255.0  # Normalize to 0-1

            # Generate Gaussian noise
            noise = np.random.normal(loc=0.0, scale=noise_level, size=data.shape)
            noisy_data = data + noise
            noisy_data = np.clip(noisy_data, 0, 1)

            noisy_img = Image.fromarray((noisy_data * 255).astype(np.uint8))

            # Re-encode as JPEG with specified quality to add compression artifacts
            noisy_img.save(output_path, format='JPEG', quality=jpeg_quality)
    except Exception as e:
        raise RuntimeError(f"Failed to add noise: {e}")

    return output_path
