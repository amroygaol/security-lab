from __future__ import annotations

import hashlib
from typing import List

from langchain_core.embeddings import Embeddings


class HashEmbeddings(Embeddings):
	"""Deterministic local embeddings for demo mode without external model dependencies."""

	def __init__(self, dimensions: int = 64) -> None:
		self.dimensions = dimensions

	def _embed(self, text: str) -> list[float]:
		digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).digest()
		values: list[float] = []
		while len(values) < self.dimensions:
			for b in digest:
				values.append((float(b) / 255.0) * 2.0 - 1.0)
				if len(values) >= self.dimensions:
					break
			digest = hashlib.sha256(digest).digest()
		return values

	def embed_documents(self, texts: List[str]) -> List[List[float]]:
		return [self._embed(t) for t in texts]

	def embed_query(self, text: str) -> List[float]:
		return self._embed(text)
