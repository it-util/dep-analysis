import requests

def scanner(dependencies):
    results = []
    url = "https://api.osv.dev/v1/query"

    for dep in dependencies:
        # { "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "3.1.4" }
        param = {
            "package": {
                "name": dep["name"],
                "ecosystem": "Go"
            },
            "version": dep["version"]
        }

        try:
            response = requests.post(url, json=param, timeout=10)

            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                
                if vulns:
                    results.append({
                        'name': dep["name"],
                        'version': dep["version"],
                        'vulnerabilities': vulns
                    })
            else:
                error = {
                    'name': dep["name"],
                    'version': dep["version"],
                    'error': f"HTTP {response.status_code}"
                }

                print(error)

        except requests.exceptions.Timeout:
            print(f"Таймаут запроса")
            results.append({
                'name': dep["name"],
                'version': dep["version"],
                'error': "Timeout"
            })
        except requests.exceptions.ConnectionError:
            print(f"Ошибка соединения")
            results.append({
                'name': dep["name"],
                'version': dep["version"],
                'error': "Connection error"
            })
        except Exception as e:
            print(f"Ошибка: {e}")
            results.append({
                'name': dep["name"],
                'version': dep["version"],
                'error': str(e)
            })

    return results