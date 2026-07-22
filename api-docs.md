# Pratima Image Engine — API Reference

Base URL: `https://pratima.homecarehelp.in`

---

## Upload Image

### `POST /upload`

**Auth:** `x-api-key: prtm_<your-company-key>`

**Content-Type:** `multipart/form-data`

| Field | Type | Description |
|-------|------|-------------|
| `image` | file | JPEG, PNG, WebP, GIF, TIFF, or PDF — max 10 MB (same field name for both images and PDFs) |
| `company_id` | string | Your company UUID |

Images are converted to WebP; PDFs are scanned and, if Ghostscript is installed on the server,
compressed — otherwise stored as-is. Either way the file is malware-scanned and encrypted at rest
before it touches disk.

The storage key (`imageId`) is a server-generated UUID — never the client's original filename — so
identical filenames from different uploads can never collide or overwrite each other. The original
filename is kept only as metadata and is returned via `Content-Disposition` when downloading.

**Response `200`**
```json
{
  "url": "http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/9f8e7d6c-5b4a-4321-9abc-def012345678.webp",
  "imageId": "9f8e7d6c-5b4a-4321-9abc-def012345678.webp",
  "companyId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "image"
}
```
`type` is `"image"` or `"pdf"`; PDFs get a `.pdf` storage key instead of `.webp`.

Note: images uploaded before this change resolve via their existing `pratima_...`-style URLs, which
continue to work unchanged.

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

No auth required by default (unless the company has a domain restriction set — see below). Returns
the file as WebP or `application/pdf` depending on what was uploaded.

```bash
curl http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/pratima_acme_phot \
  --output image.webp
```

**Use in HTML**
```html
<img src="http://139.99.133.189/img/a1b2c3d4-e5f6-7890-abcd-ef1234567890/pratima_acme_phot" />
```

---

## Restrict a Company's Files to Specific Domains

### `PUT /companies/:id/domains`

**Auth:** `x-api-key: <admin API_KEY>`

```json
{ "domains": ["backend-homecarehelp.in"] }
```

Every `GET /img/...` request for that company must then present a matching `Origin` or `Referer`
header, or it gets `403`. Pass `"domains": []` to remove the restriction (the default state for
every company — nothing changes for a company you never call this on). This is also available from
the dashboard's Companies tab ("Domains" button on each company card).

Note: browser `<img>` tags don't always send a `Referer` (e.g. under a strict `Referrer-Policy`), in
which case the request is treated as unauthorized and blocked — test the target page before relying
on this for a public-facing `<img>`.

---

## Backup & Restore a Company

### `GET /companies/:id/backup`

**Auth:** `x-api-key: <admin API_KEY>`

Downloads a ZIP of everything currently stored for that company (all files + metadata sidecars +
its `company.json` entry). Also available from the dashboard's "Backup" button per company.

### `POST /companies/:id/restore`

**Auth:** `x-api-key: <admin API_KEY>` · **Content-Type:** `multipart/form-data`, field `backup`

Restores files from a previously downloaded backup ZIP into an **existing** company (create the
company first if it no longer exists). Only restores file contents — it never overwrites the live
`apiKey`/`name`/domain settings, so restoring an old backup can't resurrect a rotated key. Also
available from the dashboard's "Restore" button per company.
