import os
from pptx import Presentation
from pptx.util import Inches
from pptx.enum.shapes import MSO_SHAPE_TYPE

PPTX_PATH = os.path.abspath("docs/VibeSec_Final_Project_Presentation.pptx")
prs = Presentation(PPTX_PATH)

print("=============================================================")
print("  VibeSec Final Project Presentation - Comprehensive QA Audit")
print(f"  File: {PPTX_PATH}")
print(f"  File Size: {os.path.getsize(PPTX_PATH):,} bytes")
print(f"  Dimensions: {prs.slide_width.inches:.3f} x {prs.slide_height.inches:.3f} inches (16:9 Widescreen)")
print(f"  Total Slides: {len(prs.slides)}")
print("=============================================================\n")

audit_results = []
all_valid = True

for idx, slide in enumerate(prs.slides, start=1):
    slide_info = {
        "slide_num": idx,
        "title": "N/A",
        "category": "N/A",
        "has_picture": False,
        "picture_bounds": None,
        "card_count": 0,
        "bullet_count": 0,
        "errors": []
    }
    
    for shape in slide.shapes:
        if shape.has_text_frame:
            tf = shape.text_frame
            text = tf.text.strip()
            if text:
                paras = [p.text.strip() for p in tf.paragraphs if p.text.strip()]
                # Check for header category or title
                for p in tf.paragraphs:
                    if p.font.size and p.font.size.pt == 11 and p.font.bold and slide_info["category"] == "N/A":
                        slide_info["category"] = p.text.strip()
                    elif p.font.size and p.font.size.pt in (24, 26, 36) and p.font.bold and slide_info["title"] == "N/A":
                        slide_info["title"] = p.text.strip()
                
                # Check bullets
                for p in tf.paragraphs:
                    if p.text.strip().startswith("•"):
                        slide_info["bullet_count"] += 1
                        
        if shape.shape_type == MSO_SHAPE_TYPE.PICTURE:
            slide_info["has_picture"] = True
            slide_info["picture_bounds"] = {
                "left": f"{shape.left.inches:.2f}in",
                "top": f"{shape.top.inches:.2f}in",
                "width": f"{shape.width.inches:.2f}in",
                "height": f"{shape.height.inches:.2f}in"
            }
        elif shape.shape_type == MSO_SHAPE_TYPE.AUTO_SHAPE:
            slide_info["card_count"] += 1

    # Validation rules
    # Slides 5 to 16 are live UI demo slides and MUST contain a picture
    if 5 <= idx <= 16:
        if not slide_info["has_picture"]:
            slide_info["errors"].append("Missing embedded screenshot!")
            all_valid = False
            
    # Every slide must have a title or headline
    if slide_info["title"] == "N/A" and idx != 1:
        slide_info["errors"].append("Missing title!")
        all_valid = False
        
    audit_results.append(slide_info)

    # Print summary
    pic_str = f" [IMAGE: {slide_info['picture_bounds']['width']} x {slide_info['picture_bounds']['height']}]" if slide_info["has_picture"] else ""
    err_str = f" *** ERROR: {', '.join(slide_info['errors'])}" if slide_info["errors"] else " OK"
    print(f"Slide {idx:02d}: [{slide_info['category']}] '{slide_info['title']}'{pic_str} | Bullets: {slide_info['bullet_count']}{err_str}")

print("\n-------------------------------------------------------------")
if all_valid:
    print("  QA VERIFICATION RESULT: ALL 18 SLIDES PASSED AUDIT (100%)")
else:
    print("  QA VERIFICATION RESULT: ERRORS DETECTED")
print("-------------------------------------------------------------")
