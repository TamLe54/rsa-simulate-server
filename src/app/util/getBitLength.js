const getBitLength = (text) => {
  const encoder = new TextEncoder('utf-8')
  const bytes = encoder.encode(text)
  return bytes.length * 8
}

module.exports = getBitLength
