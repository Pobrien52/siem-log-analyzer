import json
from datetime import datetime


def generate_report(alerts, output_file):
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with open(output_file, "w") as file:
        json.dump(report, file, indent=4)

    print(f"Report generated: {output_file}")
