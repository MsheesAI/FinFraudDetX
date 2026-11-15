import os
import re
from typing import Literal, TypedDict

from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel

load_dotenv()

MODEL_NAME = os.getenv("GROQ_MODEL")


class Verdict(BaseModel):
    """The only two allowed answers."""

    verdict: Literal["scam", "not scam"]


class State(TypedDict, total=False):
    text: str
    signals: list[str]
    verdict: str

URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
SIGNAL_PATTERNS = {
    "contains link": URL_RE,
    "urgency / threat": re.compile(
        r"\b(urgent|immediately|within 24 hours|act now|last chance|suspended|blocked|final notice)\b", re.I
    ),
    "asks for OTP/password/PIN/CNIC": re.compile(
        r"\b(otp|one[- ]time (code|password)|password|pin|cvv|cnic|ssn|card number)\b", re.I
    ),
    "unusual payment method": re.compile(
        r"\b(gift ?card|crypto|bitcoin|usdt|western union|wire transfer|easypaisa|jazzcash|advance fee)\b", re.I
    ),
    "too-good-to-be-true reward": re.compile(
        r"\b(you('ve| have) won|lottery|prize|jackpot|free money|guaranteed returns?|double your)\b", re.I
    ),
}


def extract_signals(state: State) -> State:
    text = state["text"]
    found = [name for name, pat in SIGNAL_PATTERNS.items() if pat.search(text)]
    return {"signals": found}


_prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a fraud-detection classifier. Decide whether the given message, "
            "offer, email, link description or situation is a scam. "
            "Answer ONLY with 'scam' or 'not scam'. "
            "Use the heuristic signals as hints, not as proof: a legitimate message can "
            "contain a link or mention payment.",
        ),
        ("human", "Heuristic signals: {signals}\n\nContent to analyze:\n\"\"\"\n{text}\n\"\"\""),
    ]
)


def _build_chain():
    llm = ChatGroq(model=MODEL_NAME, temperature=0)
    return _prompt | llm.with_structured_output(Verdict)


_chain = None


def classify(state: State) -> State:
    global _chain
    if _chain is None:
        _chain = _build_chain()
    result: Verdict = _chain.invoke(
        {"text": state["text"], "signals": ", ".join(state.get("signals", [])) or "none"}
    )
    return {"verdict": result.verdict}



def finalize(state: State) -> State:
    v = state.get("verdict", "").strip().lower()
    return {"verdict": "scam" if v == "scam" else "not scam"}


def build_graph():
    g = StateGraph(State)
    g.add_node("extract_signals", extract_signals)
    g.add_node("classify", classify)
    g.add_node("finalize", finalize)
    g.add_edge(START, "extract_signals")
    g.add_edge("extract_signals", "classify")
    g.add_edge("classify", "finalize")
    g.add_edge("finalize", END)
    return g.compile()