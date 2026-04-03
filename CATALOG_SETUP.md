# Catalog Setup

Instructions for fetching the Red Hat operator index catalogs and generating the namespace→VEX prefix map used by `triage.py`.

---

## 1. Install `opm`

### macOS — Apple Silicon (M1/M2/M3)
```bash
curl -LO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/opm-mac-arm64.tar.gz
tar -xvf opm-mac-arm64.tar.gz
chmod +x opm
sudo mv ./opm /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/opm
```

### macOS — Intel
```bash
curl -LO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/opm-mac.tar.gz
tar -xvf opm-mac.tar.gz
chmod +x opm
sudo mv ./opm /usr/local/bin/
xattr -d com.apple.quarantine /usr/local/bin/opm
```

### Linux (x86_64)
```bash
curl -LO https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/latest/opm-linux.tar.gz
tar -xvf opm-linux.tar.gz
chmod +x opm
sudo mv ./opm /usr/local/bin/
```

---

## 2. Configure container policy

Required so `opm` can pull images without signature verification:

```bash
mkdir -p ~/.config/containers
cat > ~/.config/containers/policy.json <<'EOF'
{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ]
}
EOF
```

---

## 3. Authenticate with Red Hat registry

Set your pull secret (download from https://console.redhat.com/openshift/install/pull-secret):

```bash
export REGISTRY_AUTH_FILE=~/pullsecret.txt
```

---

## 4. Render the operator index catalogs

```bash
mkdir -p data/catalogs

opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 -o json > data/catalogs/catalog-4.18.json
opm render registry.redhat.io/redhat/redhat-operator-index:v4.19 -o json > data/catalogs/catalog-4.19.json
opm render registry.redhat.io/redhat/redhat-operator-index:v4.20 -o json > data/catalogs/catalog-4.20.json
opm render registry.redhat.io/redhat/redhat-operator-index:v4.21 -o json > data/catalogs/catalog-4.21.json
```

Each render may take a few minutes depending on network speed.

> **Naming convention is required.**  
> Files must follow the exact pattern `catalog-{MAJOR}.{MINOR}.json` (e.g. `catalog-4.21.json`).  
> `triage_operators.py` discovers available versions and maps `--version` arguments entirely from the filename — the file content contains no catalog-level version declaration.  
> Renaming or deviating from this pattern will cause the version to be ignored or misidentified.

---

## 5. Generate the namespace map

```bash
python3 build_ns_map.py
```

This reads every `catalog*.json` from `data/catalogs/`, extracts the registry namespace, OLM package name, and operator display name for each bundle, normalises them to snake_case VEX-prefix candidates, and writes the result to `data/ns_vex_prefixes.json`.

`triage.py` loads this file automatically at startup.

---

## Updating for a new OCP release

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.22 -o json > data/catalogs/catalog-4.22.json
python3 build_ns_map.py
```

The filename `catalog-4.22.json` is what registers `4.22` as an available version — ensure it matches the index tag.
