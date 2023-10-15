const { MODULE_LENGTH } = require('../constants')

class BufferHandle {
  split(data, type) {
    const dataBuffer = Buffer.from(data, type)
    const smallerPieces = []
    const maxLengthBits = type === 'utf-8' ? MODULE_LENGTH / 2 : MODULE_LENGTH

    const numChunks = Math.ceil((dataBuffer.length * 8) / maxLengthBits)

    // Iterate to split the Buffer into smaller chunks
    for (let i = 0; i < numChunks; i++) {
      const start = (i * maxLengthBits) / 8 // Calculate the start index
      const end = Math.min(((i + 1) * maxLengthBits) / 8, dataBuffer.length) // Calculate the end index
      const chunk = dataBuffer.slice(start, end)
      smallerPieces.push(chunk)
    }
    return smallerPieces
  }

  splitUTF8(data) {
    return this.split(data, 'utf-8')
  }

  splitBase64(data) {
    return this.split(data, 'base64')
  }

  join(chunks) {
    return Buffer.concat(chunks)
  }
}

module.exports = new BufferHandle()
