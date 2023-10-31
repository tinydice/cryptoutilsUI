import qrcode
from PIL import Image

def generate_qr_code(text, filename):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    img.save(filename)

if __name__ == "__main__":
    # Input the text you want to encode into the QR code
    input_text = ""

    # Provide a filename for the QR code image
    output_filename = "qr_code.png"

    generate_qr_code(input_text, output_filename)

    # Display the QR code using Pillow
    qr_image = Image.open(output_filename)
    qr_image.show()