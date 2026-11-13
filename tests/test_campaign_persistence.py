from gpuvulnagent.agents.langgraph_agent import Campaign


def test_state_survives_a_new_object(tmp_path):
    c = Campaign(tmp_path, campaign_id="c1", goal="g")
    c.observation("container_exec", True, "run1#7")
    c.claim("FACT_CLAIM", "unverified", [], promoted=False)
    c.fact("verified", ["run1#7"])
    c.next_step("run matrix")
    c.data["spent_tokens"] = 1234
    c.save()
    again = Campaign(tmp_path, campaign_id="c1", goal="g")
    assert again.data["observations"][0]["evidence_id"] == "run1#7"
    assert again.data["facts"][0]["text"] == "verified"
    assert again.data["claims"][0]["promoted"] is False
    assert again.data["next_steps"] == ["run matrix"]
    assert again.data["spent_tokens"] == 1234


def test_claim_without_evidence_is_not_a_fact(tmp_path):
    c = Campaign(tmp_path, campaign_id="c2", goal="g")
    c.claim("FACT_CLAIM", "crashes", promoted=False)
    assert c.data["facts"] == []
