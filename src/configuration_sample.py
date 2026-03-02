import os

from pentester.config import TargetType, clear_settings_cache, get_settings

# --- 1. Show defaults ---
settings = get_settings()
print("=== Default settings ===")
print(f"  output_dir  : {settings.output_dir}")
print(f"  target_type : {settings.target_type}")
print(f"  target_type value: {settings.target_type.value!r}")

# --- 2. Singleton caching ---
settings2 = get_settings()
print("\n=== Singleton cache ===")
print(f"  get_settings() is get_settings(): {settings is settings2}")

# --- 3. re-read after cache clear + env override ---
os.environ["PENTESTER_OUTPUT_DIR"] = "/tmp/demo-scan"
os.environ["PENTESTER_TARGET_TYPE"] = "LLM"
clear_settings_cache()

overridden = get_settings()
print("\n=== After env var override + cache clear ===")
print(f"  output_dir  : {overridden.output_dir}")
print(f"  target_type : {overridden.target_type}")

# --- 4. Show TargetType enum members ---
print("\n=== TargetType members ===")
for member in TargetType:
    print(f"  {member.name} = {member.value!r}")

# --- 5. Direct instantiation with constructor overrides ---
custom = TargetType.LLM
print("\n=== Direct TargetType usage ===")
print(f"  custom type : {custom}  (is str: {isinstance(custom, str)})")
