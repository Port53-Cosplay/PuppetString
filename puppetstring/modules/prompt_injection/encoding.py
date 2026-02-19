"""Unicode encoder — steganographic encoding techniques for hiding text.

HOW THIS WORKS:

    LLMs read text as tokens. Some Unicode characters are invisible to humans
    but still tokenized and "seen" by models. We exploit this to hide adversarial
    instructions in plain-looking text.

    Four techniques, from most to least stealthy:

    1. ZERO-WIDTH ENCODING
       Uses zero-width characters (U+200B, U+200C, U+200D, U+FEFF) to encode
       binary data. Each character of the hidden message is converted to 8 bits,
       and each bit is mapped to one of two invisible characters. The result is
       a string of invisible characters that can be inserted anywhere in text.
       Humans see nothing; LLMs see the tokens.

    2. TAG CHARACTERS (U+E0001-U+E007F)
       Unicode "language tag" characters are invisible in most renderers but
       encode ASCII directly (tag char = U+E0000 + ASCII code point). Originally
       meant for language metadata, now deprecated — perfect for hiding text.

    3. HOMOGLYPH SUBSTITUTION
       Replace Latin characters with visually identical Cyrillic or Greek
       characters. "Hello" becomes "Неllо" (Cyrillic Н, Latin ell, Cyrillic о).
       Humans can't tell the difference; LLMs may tokenize them differently,
       causing subtle behavioral changes.

    4. INVISIBLE SEPARATORS
       Insert invisible Unicode separators (Word Joiner U+2060, Invisible Times
       U+2062, etc.) between characters. Models see these as tokens; humans don't.
"""

from __future__ import annotations

# ── Zero-width character encoding ─────────────────────────────────
# We use two invisible characters to represent binary 0 and 1.
# A third character acts as a delimiter between bytes.

_ZW_ZERO = "\u200b"  # Zero-Width Space = binary 0
_ZW_ONE = "\u200c"  # Zero-Width Non-Joiner = binary 1
_ZW_DELIM = "\u200d"  # Zero-Width Joiner = byte delimiter
_ZW_START = "\ufeff"  # BOM = marks start of encoded block


class UnicodeEncoder:
    """Encodes and decodes hidden text using various Unicode steganography techniques."""

    # ── Zero-width encoding ───────────────────────────────────────

    @staticmethod
    def zero_width_encode(text: str) -> str:
        """Encode text as invisible zero-width characters.

        Each character is converted to its UTF-8 bytes, each byte to 8 bits,
        and each bit to a zero-width character. Bytes are separated by a
        delimiter character.

        Args:
            text: The text to hide.

        Returns:
            A string of invisible characters that encodes the input.
        """
        if not text:
            return ""

        encoded_bytes: list[str] = []
        for byte in text.encode("utf-8"):
            bits = format(byte, "08b")
            encoded_bits = bits.replace("0", _ZW_ZERO).replace("1", _ZW_ONE)
            encoded_bytes.append(encoded_bits)

        return _ZW_START + _ZW_DELIM.join(encoded_bytes)

    @staticmethod
    def zero_width_decode(encoded: str) -> str:
        """Decode a zero-width-encoded string back to plaintext.

        Args:
            encoded: A string of zero-width characters.

        Returns:
            The original hidden text.

        Raises:
            ValueError: If the encoded string is malformed.
        """
        # Strip the start marker if present
        if encoded.startswith(_ZW_START):
            encoded = encoded[len(_ZW_START) :]

        if not encoded:
            return ""

        # Split on byte delimiter
        byte_strings = encoded.split(_ZW_DELIM)

        decoded_bytes: list[int] = []
        for byte_str in byte_strings:
            if not byte_str:
                continue
            # Convert zero-width chars back to bits
            bits = byte_str.replace(_ZW_ZERO, "0").replace(_ZW_ONE, "1")
            # Validate: should be exactly 8 binary digits
            if len(bits) != 8 or not all(b in "01" for b in bits):
                msg = f"Invalid zero-width byte encoding: got {len(bits)} bits"
                raise ValueError(msg)
            decoded_bytes.append(int(bits, 2))

        return bytes(decoded_bytes).decode("utf-8")

    @staticmethod
    def zero_width_inject(visible_text: str, hidden_text: str) -> str:
        """Insert hidden text encoded as zero-width chars into visible text.

        The hidden text is placed right after the first word of the visible
        text, making it invisible but present in the token stream.

        Args:
            visible_text: The text that humans see.
            hidden_text: The text to hide inside it.

        Returns:
            The visible text with invisible encoded text embedded.
        """
        encoded = UnicodeEncoder.zero_width_encode(hidden_text)

        # Insert after first space (or at start if no spaces)
        space_idx = visible_text.find(" ")
        if space_idx == -1:
            return visible_text + encoded
        return visible_text[: space_idx + 1] + encoded + visible_text[space_idx + 1 :]

    # ── Tag character encoding ────────────────────────────────────
    # Unicode tag characters U+E0001-U+E007F map directly to ASCII.
    # U+E0000 + ascii_code_point = tag character.

    _TAG_OFFSET = 0xE0000

    @staticmethod
    def tag_encode(text: str) -> str:
        """Encode ASCII text as Unicode tag characters.

        Only works for ASCII characters (0x01-0x7F). Non-ASCII characters
        are silently skipped.

        Args:
            text: ASCII text to hide.

        Returns:
            A string of invisible tag characters.
        """
        result: list[str] = []
        for char in text:
            code = ord(char)
            if 0x01 <= code <= 0x7F:
                result.append(chr(UnicodeEncoder._TAG_OFFSET + code))
        return "".join(result)

    @staticmethod
    def tag_decode(encoded: str) -> str:
        """Decode tag characters back to ASCII text.

        Args:
            encoded: A string of tag characters.

        Returns:
            The original ASCII text.
        """
        result: list[str] = []
        for char in encoded:
            code = ord(char)
            if 0xE0001 <= code <= 0xE007F:
                result.append(chr(code - UnicodeEncoder._TAG_OFFSET))
        return "".join(result)

    @staticmethod
    def tag_inject(visible_text: str, hidden_text: str) -> str:
        """Insert tag-encoded hidden text into visible text.

        Args:
            visible_text: The text that humans see.
            hidden_text: The ASCII text to hide.

        Returns:
            The visible text with tag-encoded text appended.
        """
        encoded = UnicodeEncoder.tag_encode(hidden_text)
        return visible_text + encoded

    # ── Homoglyph substitution ────────────────────────────────────
    # Maps Latin characters to visually identical Cyrillic/Greek characters.

    _HOMOGLYPHS: dict[str, str] = {
        "A": "\u0410",  # Cyrillic А
        "B": "\u0412",  # Cyrillic В
        "C": "\u0421",  # Cyrillic С
        "E": "\u0415",  # Cyrillic Е
        "H": "\u041d",  # Cyrillic Н
        "K": "\u041a",  # Cyrillic К
        "M": "\u041c",  # Cyrillic М
        "O": "\u041e",  # Cyrillic О
        "P": "\u0420",  # Cyrillic Р
        "T": "\u0422",  # Cyrillic Т
        "X": "\u0425",  # Cyrillic Х
        "a": "\u0430",  # Cyrillic а
        "c": "\u0441",  # Cyrillic с
        "e": "\u0435",  # Cyrillic е
        "o": "\u043e",  # Cyrillic о
        "p": "\u0440",  # Cyrillic р
        "x": "\u0445",  # Cyrillic х
        "y": "\u0443",  # Cyrillic у
    }

    _REVERSE_HOMOGLYPHS: dict[str, str] = {v: k for k, v in _HOMOGLYPHS.items()}

    @staticmethod
    def homoglyph_replace(text: str) -> str:
        """Replace Latin characters with Cyrillic/Greek lookalikes.

        This doesn't hide text — it disguises it. The text looks identical
        to humans but uses different Unicode code points, which may cause
        LLMs to tokenize and process it differently.

        Args:
            text: Text with Latin characters.

        Returns:
            Text with some Latin chars replaced by homoglyphs.
        """
        return "".join(UnicodeEncoder._HOMOGLYPHS.get(c, c) for c in text)

    @staticmethod
    def homoglyph_restore(text: str) -> str:
        """Restore homoglyph-substituted text back to Latin characters.

        Args:
            text: Text with Cyrillic/Greek homoglyphs.

        Returns:
            Text with homoglyphs replaced by Latin equivalents.
        """
        return "".join(UnicodeEncoder._REVERSE_HOMOGLYPHS.get(c, c) for c in text)

    # ── Invisible separators ──────────────────────────────────────
    # Insert invisible Unicode characters between visible characters.
    # These are tokenized by LLMs but invisible to humans.

    _SEPARATORS = [
        "\u2060",  # Word Joiner
        "\u2062",  # Invisible Times
        "\u2063",  # Invisible Separator
        "\u2064",  # Invisible Plus
    ]

    @staticmethod
    def separator_inject(visible_text: str, hidden_text: str) -> str:
        """Hide text by interleaving invisible separators that encode data.

        Each character of the hidden text is mapped to a sequence of invisible
        separators using base-4 encoding (4 separator types = 2 bits each).

        Args:
            visible_text: The text that humans see.
            hidden_text: The text to hide.

        Returns:
            The visible text with invisible separators encoding the hidden text.
        """
        if not hidden_text:
            return visible_text

        separators = UnicodeEncoder._SEPARATORS

        # Encode each hidden byte as a sequence of base-4 digits
        encoded_parts: list[str] = []
        for byte in hidden_text.encode("utf-8"):
            # Convert byte to base-4 (4 digits, each 0-3)
            digits: list[int] = []
            val = byte
            for _ in range(4):
                digits.append(val % 4)
                val //= 4
            digits.reverse()
            encoded_parts.append("".join(separators[d] for d in digits))

        # Concatenate directly — each byte is exactly 4 chars, no delimiter needed
        encoded = "".join(encoded_parts)

        # Insert at a natural break point in the visible text
        mid = len(visible_text) // 2
        return visible_text[:mid] + encoded + visible_text[mid:]

    @staticmethod
    def separator_extract(text: str) -> str:
        """Extract hidden text from separator-encoded content.

        Args:
            text: Text potentially containing encoded separators.

        Returns:
            The hidden text, or empty string if no encoded data found.
        """
        separators = UnicodeEncoder._SEPARATORS
        sep_set = set(separators)

        # Extract only the separator characters
        sep_chars = [c for c in text if c in sep_set]
        if not sep_chars:
            return ""

        # The delimiter is two word joiners in sequence — but they're also
        # part of the encoding. We split on chunks of 4 separator chars.
        # Each byte = 4 base-4 digits = 4 separator chars.

        # Build separator-to-digit mapping
        sep_to_digit = {s: i for i, s in enumerate(separators)}

        decoded_bytes: list[int] = []
        i = 0
        while i + 3 < len(sep_chars):
            digits = [sep_to_digit.get(sep_chars[i + j], 0) for j in range(4)]
            val = digits[0] * 64 + digits[1] * 16 + digits[2] * 4 + digits[3]
            if 0 <= val <= 255:
                decoded_bytes.append(val)
            i += 4

        try:
            return bytes(decoded_bytes).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return ""
