import struct, sys, re

def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

class PE:
    def __init__(self,path):
        self.path=path
        self.b=open(path,'rb').read()
        b=self.b
        e=u32(b,0x3C)
        assert b[e:e+4]==b'PE\0\0', 'not PE'
        self.num=u16(b,e+6); self.opt_size=u16(b,e+20)
        opt=e+24
        self.magic=u16(b,opt)
        self.pe32plus = self.magic==0x20b
        self.image_base = u64(b,opt+24) if self.pe32plus else u32(b,opt+28)
        self.size_image = u32(b,opt+56)
        self.sec_off = opt+self.opt_size
        self.sections=[]
        for i in range(self.num):
            o=self.sec_off+i*40
            name=b[o:o+8].rstrip(b'\0').decode('latin1')
            vsize=u32(b,o+8); vaddr=u32(b,o+12); rsize=u32(b,o+16); raddr=u32(b,o+20)
            chars=u32(b,o+36)
            self.sections.append(dict(name=name,vsize=vsize,vaddr=vaddr,rsize=rsize,raddr=raddr,chars=chars))
    def rva_to_off(self,rva):
        for s in self.sections:
            if s['vaddr']<=rva<s['vaddr']+max(s['vsize'],s['rsize']):
                return s['raddr']+(rva-s['vaddr'])
        return None
    def off_to_rva(self,off):
        for s in self.sections:
            if s['raddr']<=off<s['raddr']+s['rsize']:
                return s['vaddr']+(off-s['raddr'])
        return None
    def read_off(self,off,n): return self.b[off:off+n]

def fixed_version(pe):
    b=pe.b
    sig=struct.pack('<I',0xFEEF04BD)
    i=b.find(sig)
    while i!=-1:
        if i+0x10<=len(b):
            ms=u32(b,i+8); ls=u32(b,i+12)
            return (ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)
        i=b.find(sig,i+1)
    return None

def scan(pe,pat):
    b=pe.b
    # pat: list of int or None
    n=len(pat); out=[]
    first=pat[0]
    start=0
    while True:
        i=b.find(bytes([first]),start)
        if i<0: break
        ok=True
        for k,p in enumerate(pat):
            if p is not None and b[i+k]!=p: ok=False; break
        if ok: out.append(i)
        start=i+1
    return out

def stores(pe,fn_off,limit=0x400):
    b=pe.b
    end=fn_off+limit
    out=[]
    i=fn_off
    while i<end-10:
        nxt=pe.off_to_rva(i)
        if nxt is None: break
        rex=0
        j=i
        if 0x40<=b[j]<=0x4F:
            rex=1; j+=1
        op=b[j]
        if j+1<len(b) and b[j+1]==0x05 and op in (0x88,0x89,0xC6,0xC7):
            width={0x88:1,0x89:4,0xC6:1,0xC7:4}[op]
            disp=struct.unpack_from('<i',b,j+2)[0]
            total=(j-i)+6+(0 if width==4 and op in (0x88,0x89) else (1 if op==0xC6 else (4 if op==0xC7 else 0)))
            # 88/89: op+modrm+disp32 = 6 bytes from op; C6: 7; C7: 10
            if op in (0x88,0x89): length=(j-i)+6
            elif op==0xC6: length=(j-i)+7
            else: length=(j-i)+10
            val=None
            if op==0xC6: val=b[j+6]
            elif op==0xC7: val=struct.unpack_from('<I',b,j+6)[0]
            out.append((width, nxt+length+disp, val)); i+=length; continue
        i+=1
    return out

for path in sys.argv[1:]:
    pe=PE(path)
    print('==',path)
    print('fixed',fixed_version(pe),'imagebase',hex(pe.image_base),'size',hex(pe.size_image))
    for n,pat in [
        ('LocalOnly',[0x74,None,0x83,0x3D,None,None,None,None,0x02]),
        ('SingleUser',[0x48,0xFF,0x15,None,None,None,None,0x0F,0x1F,0x44,0x00,0x00,0x85,0xC0,0x0F,0x84]),
        ('DefPolicy',[0x44,0x8B,0x8F,0x38,0x06,0x00,0x00,0x45,0x3B,0xC1,0x75]),
        ('SLInit',[0x40,0x57,0x48,0x81,0xEC,0xA0,0x05,0x00,0x00,0x48,0x8B,0x05]),
    ]:
        m=scan(pe,pat)
        print(n,len(m),[hex(x) for x in m[:5]])
    m=scan(pe,[0x40,0x57,0x48,0x81,0xEC,0xA0,0x05,0x00,0x00,0x48,0x8B,0x05])
    if m:
        st=stores(pe,m[0],limit=0x1000)
        st=[x for x in st if 0x120000 <= x[1] < 0x140000]
        print('stores_globals',[(t,hex(a),v) for t,a,v in st])
    print('long LocalOnly',len(scan(pe,[0x74,0x44,0x83,0x3D,None,None,None,None,0x02,0xBB,0x05,0x00,0x07,0x80,0x0F,0x86,0xC9,0x00,0x00,0x00,0x48,0x8D,0x05])))
    print('long SingleUser',len(scan(pe,[0x48,0xFF,0x15,None,None,None,None,0x0F,0x1F,0x44,0x00,0x00,0x85,0xC0,0x0F,0x84,0x88,0x01,0x00,0x00,0x41,0xB9,0x19,0x00,0x02,0x00,0x4C,0x8D,0x05])))
