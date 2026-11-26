"""Regression tests for offset-dependent production-boundary source data."""

import hashlib
import unittest

from scripts.generate_split_qualification_source import (
    CONTENT_BLOCK_SIZE,
    SEGMENT_LIMIT,
    WRITE_CHUNK_SIZE,
    content_chunk,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SplitQualificationSourceTests(unittest.TestCase):
    def test_selecting_a_different_segment_changes_the_digest(self) -> None:
        segment_one = content_chunk(SEGMENT_LIMIT, WRITE_CHUNK_SIZE)
        wrong_segment = content_chunk(0, WRITE_CHUNK_SIZE)

        self.assertNotEqual(sha256(segment_one), sha256(wrong_segment))

    def test_same_chunk_repeats_but_adjacent_chunks_differ(self) -> None:
        first = content_chunk(0, WRITE_CHUNK_SIZE)
        repeated = content_chunk(0, WRITE_CHUNK_SIZE)
        later = content_chunk(WRITE_CHUNK_SIZE, WRITE_CHUNK_SIZE)

        self.assertEqual(sha256(first), sha256(repeated))
        self.assertNotEqual(sha256(first), sha256(later))

    def test_wrong_aligned_offset_changes_the_digest(self) -> None:
        boundary_block = content_chunk(SEGMENT_LIMIT, CONTENT_BLOCK_SIZE)
        preceding_block = content_chunk(SEGMENT_LIMIT - CONTENT_BLOCK_SIZE, CONTENT_BLOCK_SIZE)

        self.assertEqual(SEGMENT_LIMIT % CONTENT_BLOCK_SIZE, 0)
        self.assertNotEqual(sha256(boundary_block), sha256(preceding_block))


if __name__ == "__main__":
    unittest.main()
