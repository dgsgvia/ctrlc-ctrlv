/**
 * Extrae el ID de un video de YouTube de diferentes formatos de URL
 * @param {string} url - La URL del video de YouTube
 * @returns {string|null} 
 *
 * Soporta formatos:
 * - https://www.youtube.com/watch?v=VIDEO_ID
 * - https://youtu.be/VIDEO_ID
 * - https://www.youtube.com/embed/VIDEO_ID
 * - https://www.youtube.com/v/VIDEO_ID
 */
function extractYouTubeId(url) {
  if (!url || typeof url !== "string") return null

  const patterns = [
    /(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/,
    /youtube\.com\/embed\/([a-zA-Z0-9_-]{11})/,
    /youtube\.com\/v\/([a-zA-Z0-9_-]{11})/,
    /youtube\.com\/\?v=([a-zA-Z0-9_-]{11})/,
  ]

  for (const pattern of patterns) {
    const match = url.match(pattern)
    if (match && match[1]) {
      return match[1]
    }
  }

  if (/^[a-zA-Z0-9_-]{11}$/.test(url)) {
    return url
  }

  return null
}

/**
 * Convierte cualquier URL de YouTube a formato estándar para Video.js
 * @param {string} url - La URL del video
 * @returns {string|null} - URL en formato watch?v= o null
 */
function normalizeYouTubeUrl(url) {
  const videoId = extractYouTubeId(url)
  return videoId ? `https://www.youtube.com/watch?v=${videoId}` : null
}

/**
 * Verifica si una URL es de YouTube
 * @param {string} url - La URL a verificar
 * @returns {boolean}
 */
function isYouTubeUrl(url) {
  if (!url || typeof url !== "string") return false
  return url.includes("youtube.com") || url.includes("youtu.be")
}
