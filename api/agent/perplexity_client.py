import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Perplexity uses OpenAI's library structure for their API
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY", "")

# We configure to base_url="https://api.perplexity.ai" as per their documentation
try:
    client = OpenAI(api_key=PERPLEXITY_API_KEY, base_url="https://api.perplexity.ai")
except Exception as e:
    client = None

def ask_intel_agent(query: str, dashboard_context: str = "", history: list = None) -> str:
    """
    Answers a threat intelligence query using Perplexity's sonar models.
    """
    if not PERPLEXITY_API_KEY:
        return "ERROR: PERPLEXITY_API_KEY not configured in environment."

    if history is None:
        history = []

    system_prompt = (
        "You are PHANTOM_EYE, an elite Tier-3 Cyber Security Analyst engine. "
        "You output highly concise, factual threat intelligence. DO NOT output generic disclaimers. "
        "Always search the live web for the latest tactical news on the queried indicators. "
        "Use Markdown formatting, bold key terms, and always provide specific actionable context."
    )
    
    if dashboard_context:
        system_prompt += f"\n\nCURRENT ML SCORING CONTEXT:\n{dashboard_context}"

    messages = [{"role": "system", "content": system_prompt}]
    
    # Perplexity API requires strict interleaving: user, assistant, user, assistant...
    # We must ensure history does not start with an assistant message, nor have two of the same role in a row.
    valid_history = []
    
    for msg in history:
        r = msg.get("role", "user")
        
        # Skip the hardcoded frontend welcome message
        if "SYSTEM ONLINE" in msg.get("content", ""):
            continue
            
        if len(valid_history) == 0:
            if r == "assistant":
                continue # Cannot start with assistant
            valid_history.append({"role": r, "content": msg.get("content", "")})
        else:
            last_role = valid_history[-1]["role"]
            if r == last_role:
                # Same role twice in a row, concatenate them to maintain interleaving
                valid_history[-1]["content"] += "\n" + msg.get("content", "")
            else:
                valid_history.append({"role": r, "content": msg.get("content", "")})
    
    # Finally, append the actual query
    if len(valid_history) > 0 and valid_history[-1]["role"] == "user":
        # If history already ended with a user msg (shouldn't usually happen), concatenate to avoid double 'user'
        valid_history[-1]["content"] += "\n\nFollow up: " + query
    else:
        valid_history.append({"role": "user", "content": query})

    for vh in valid_history:
        messages.append(vh)

    try:
        response = client.chat.completions.create(
            model="sonar-pro", # Alternatively sonar-reasoning
            messages=messages,
            temperature=0.2, # Keep it strictly analytical
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AGENT KERNEL ERROR: Failed to reach Sonar Uplink. {str(e)}"
