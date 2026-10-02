"""Optional heavy vision models (YOLOv8, CLIP). Thin adapters over
`scanner.image` so nothing here is ever required to import the package.

Install them explicitly if you want object detection or CLIP similarity:

    pip install ultralytics open-clip-torch

Every adapter exposes `.available()` and returns an empty result instead of
raising when the model is missing, because a CPU-only Space has no business
downloading 2GB of weights.
"""
