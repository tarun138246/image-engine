# Pratima Image Engine — API Reference

Base URL: `http://139.99.133.189`

---

## Upload Image

### `POST /upload`

**Auth:** `x-api-key: prtm_<your-company-key>`

**Content-Type:** `multipart/form-data`

| Field | Type | Description |
|-------|------|-------------|
| `image` | file | JPEG, PNG, WebP, GIF, or TIFF — max 10 MB |
| `company_id` | string | Your company UUID |

**Response `200`**
```json
{
  "url": "http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/pratima_acme_phot",
  "imageId": "pratima_acme_phot",
  "companyId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**cURL**
```bash
curl -X POST http://139.99.133.189/upload \
  -H "x-api-key: prtm_your-company-key" \
  -F "company_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -F "image=@/path/to/photo.jpg"
```

**JavaScript**
```js
const form = new FormData();
form.append('company_id', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890');
form.append('image', fileInput.files[0]);

const res = await fetch('http://139.99.133.189/upload', {
  method: 'POST',
  headers: { 'x-api-key': 'prtm_your-company-key' },
  body: form,
});

const { url } = await res.json();
// url is the public link to the image
```

---

## Get Image

### `GET /img/:company_id/:image_id`

No auth required. Returns the image as WebP.

```bash
curl http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/pratima_acme_phot \
  --output image.webp
```

**Use in HTML**
```html
<img src="http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/pratima_acme_phot" />
```
