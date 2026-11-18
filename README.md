# ips-et-feed — feed ET para el IPS Megatron

Repositorio *serverless* que compila el feed de IPs comprometidas de
[Emerging Threats](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
en un `.rsc` que el MikroTik importa **sin parsear nada**. Todo lo que se genera
lleva el sello **`realizado por megatron`**.

```
GitHub Actions (03:17 UTC)          router (05:10 local)
  descarga ET                  ->   /tool fetch (HTTPS validado)
  sanea + colapsa              ->   /import del .rsc
  publica et-megatron.rsc      ->   verifica contador -> libera lista vieja
                                   /log info
```

## Por que se compila fuera del router

RouterOS 6.x solo expone los primeros **4095 bytes** de un fichero con
`/file get ... contents`, y `fetch output=user` devuelve `data` vacio. El feed ET
son ~8 KB, asi que el router **no puede** parsearlo por si mismo. Compilando el
`.rsc` fuera, el router solo tiene que descargar e importar: 100 % autonomo, sin
depender de ningun PC encendido.

## Contenido

| Fichero | Que es |
|---|---|
| `build_et_rsc.py` | descarga el feed, lo sanea y genera el `.rsc` |
| `tests/test_build.py` | tests del parseo, orden, guardas y metadatos |
| `et-megatron.rsc` | **artefacto** que descarga el router (lo escribe el Action) |
| `et-megatron.json` | contadores y hashes de esa generacion (auditoria) |
| `routeros/ips-et-pull.src` | cuerpo del `/system script` que hace el pull |

## Salvaguardas

- Solo IPv4 publicas: se descartan RFC1918, bogons, multicast y reservadas.
- Se colapsan solapamientos y se ordena de forma determinista (diffs limpios).
- Si el feed trae **<100** o **>5000** redes, el build falla y **no se publica**:
  el router conserva la lista anterior.
- El `.rsc` escribe `:global ipsEtCount` al final: si la importacion se corta, el
  conteo no coincide y el router descarta la lista nueva.
- El router tambien aborta si el feed cae mas del 50 % de un dia para otro.
- `check-certificate=yes` en el router: requiere la CA **ISRG Root X1** importada.

## Instalacion en el router (una vez)

1. Importar la CA de Let's Encrypt (sin ella `fetch` no valida HTTPS). El PEM
   está versionado en `routeros/certs/isrg-root-x1.pem`:

   ```routeros
   /certificate import file-name=isrg-root-x1.pem passphrase=""
   ```

2. Crear el script de pull con el contenido de `routeros/ips-et-pull.src`
   (sustituyendo `USUARIO` por tu usuario de GitHub):

   ```routeros
   /system script add name="ips-et-megatron" policy=ftp,read,write,policy,test \
     comment="IPS-MEGATRON et pull diario - realizado por megatron" \
     source=[/file get ips-et-pull.src contents]
   ```

3. Crear las listas y reglas (8 reglas: `raw` src/dst y `filter` fwd/out para A y B):

   ```routeros
   :foreach l in={"ips_megatron_et_a";"ips_megatron_et_b"} do={
     /ip firewall raw add chain=prerouting action=drop src-address-list=$l place-before=0
     /ip firewall raw add chain=prerouting action=drop dst-address-list=$l place-before=0
     /ip firewall filter add chain=forward action=drop dst-address-list=$l place-before=0
     /ip firewall filter add chain=output action=drop dst-address-list=$l place-before=0
   }
   ```

4. Programar el pull diario y probarlo:

   ```routeros
   /system scheduler add name="ips-et-megatron" interval=1d start-time=05:10:00 \
     on-event="/system script run ips-et-megatron" policy=ftp,read,write,policy,test \
     comment="IPS-MEGATRON et diario 05:10 - realizado por megatron"
   /system script run ips-et-megatron
   ```

## Verificacion

```routeros
/log print where message~"IPS-MEGATRON et"
:put [:len [/ip firewall address-list find where list=ips_megatron_et_a]]
:put [:len [/ip firewall address-list find where list=ips_megatron_et_b]]
/ping <ip-del-feed> count=3      # packet rejected
```

Se espera una lista con ~580 entradas y la otra a 0 (doble buffer).

## Ejecutar el build en local

```powershell
python build_et_rsc.py                 # descarga ET y escribe el .rsc
python build_et_rsc.py --input feed.txt --min 1
python -m pytest tests -q
```

Codigos de salida: `0` ok, `2` fallo de red, `3` feed demasiado pequeno,
`4` feed demasiado grande. En los tres ultimos **no** se escribe nada.
