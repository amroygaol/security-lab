from __future__ import annotations

from dataclasses import dataclass

try:
	from ddgs import DDGS
except ImportError:
	from duckduckgo_search import DDGS

from ...core.security import sanitize_for_llm


@dataclass
class EnrichedDoc:
	technology: str
	title: str
	url: str
	snippet: str

	def as_text(self) -> str:
		return (
			f"Technology: {self.technology}\\n"
			f"Title: {self.title}\\n"
			f"URL: {self.url}\\n"
			f"Summary: {self.snippet}"
		)


def enrich_with_duckduckgo(technologies: list[str], max_results: int) -> list[EnrichedDoc]:
	docs: list[EnrichedDoc] = []
	if not technologies:
		return docs

	with DDGS() as ddgs:
		for tech in technologies:
			query = f"latest security best practices and CVEs for {tech}"
			try:
				results = ddgs.text(query, max_results=max_results)
				for item in results:
					docs.append(
						EnrichedDoc(
							technology=sanitize_for_llm(tech),
							title=sanitize_for_llm(item.get("title", "")),
							url=sanitize_for_llm(item.get("href", "")),
							snippet=sanitize_for_llm(item.get("body", "")),
						)
					)
			except Exception:
				continue

	return docs
