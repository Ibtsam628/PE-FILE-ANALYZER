"""
Create a simple icon for the application
Run this once to generate icon.ico
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Create a new image
img = Image.new('RGB', (256, 256), color='#1a1a2e')
draw = ImageDraw.Draw(img)

# Draw border
draw.rectangle([20, 20, 236, 236], outline='#00d4ff', width=5)

# Draw text
try:
    font = ImageFont.truetype("arial.ttf", 80)
except:
    font = ImageFont.load_default()
    
draw.text((70, 90), "PE", fill='#00d4ff', font=font)
draw.text((70, 160), "Analyzer", fill='#00d4ff', font=ImageFont.load_default())

# Save as ICO
icon_dir = 'icons'
if not os.path.exists(icon_dir):
    os.makedirs(icon_dir)

icon_path = os.path.join(icon_dir, 'icon.ico')
img.save(icon_path, format='ICO', sizes=[(256, 256)])
print(f"Icon created: {os.path.abspath(icon_path)}")
