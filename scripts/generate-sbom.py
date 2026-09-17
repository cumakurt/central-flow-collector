#!/usr/bin/env python3
import hashlib,json,os,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
identity=json.loads((root/'project.json').read_text())
out=Path(os.environ.get('OUT_DIR',root/'dist'))
out.mkdir(parents=True,exist_ok=True)
version=os.environ.get('VERSION','4.0.0')
files=[]
for p in sorted(out.glob('*')):
    if p.is_file() and not p.name.startswith('SBOM.') and 'checksums' not in p.name:
        h=hashlib.sha256(p.read_bytes()).hexdigest(); files.append({'path':'dist/'+p.name,'sha256':h,'size':p.stat().st_size})
spdx={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':f'central-flow-collector-{version}','documentNamespace':f'https://central-flow-collector.local/sbom/{version}/{int(time.time())}','creationInfo':{'created':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'creators':['Tool: scripts/generate-sbom.py']},'packages':[{'name':'central-flow-collector','SPDXID':'SPDXRef-Package','versionInfo':version,'downloadLocation':identity['source'],'homepage':identity['source'],'supplier':f"Person: {identity['developer']} ({identity['email']})",'copyrightText':identity['copyright'],'filesAnalyzed':False,'licenseConcluded':identity['license'],'licenseDeclared':identity['license']}],'externalRefs':[],'files':files}
(out/'SBOM.spdx.json').write_text(json.dumps(spdx,indent=2)+'\n')
cdx={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'authors':[{'name':identity['developer'],'email':identity['email']}],'component':{'type':'application','name':'central-flow-collector','version':version,'licenses':[{'license':{'id':identity['license']}}],'externalReferences':[{'type':'vcs','url':identity['source']}]}},'components':[],'properties':[{'name':'go.module','value':'central-flow-collector'},{'name':'third_party_go_modules','value':'0'}]}
(out/'SBOM.cdx.json').write_text(json.dumps(cdx,indent=2)+'\n')
