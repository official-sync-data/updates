$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$PublicDir = Join-Path $Root "public"
if (-not (Test-Path -LiteralPath $PublicDir)) {
    $PublicDir = $Root
}
$PublicDatasetsDir = Join-Path $PublicDir "datasets"
$AndroidProjectCandidate = Join-Path $Root "..\work\BloqueurAppels"
$PublicKey = Join-Path $PublicDir "official_update_public_key.pem"
if (Test-Path -LiteralPath $AndroidProjectCandidate) {
    $Project = Resolve-Path $AndroidProjectCandidate
    $AndroidPublicKey = Join-Path $Project "app\src\main\res\raw\official_update_public_key.pem"
    if (Test-Path -LiteralPath $AndroidPublicKey) {
        $PublicKey = $AndroidPublicKey
    }
}
$Manifest = Join-Path $PublicDir "manifest.json"
$Signature = Join-Path $PublicDir "manifest.sig"

if (-not (Test-Path -LiteralPath $PublicKey)) { throw "Cle publique Android absente." }
if (-not (Test-Path -LiteralPath $Manifest)) { throw "Manifeste absent." }
if (-not (Test-Path -LiteralPath $Signature)) { throw "Signature absente." }
if (-not (Test-Path -LiteralPath $PublicDatasetsDir)) { throw "Dossier datasets absent." }

$errors = New-Object System.Collections.Generic.List[string]

function Add-Error($message) {
    $errors.Add([string]$message) | Out-Null
    Write-Output "ERREUR: $message"
}

function Get-DatasetFileName($url) {
    try {
        $uri = [System.Uri]::new([string]$url)
        return [System.IO.Path]::GetFileName($uri.AbsolutePath)
    } catch {
        return ""
    }
}

function Read-GzipJson {
    param([string]$Path)

    $inputStream = [System.IO.File]::OpenRead($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new(
                $inputStream,
                [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new(
                    $gzipStream,
                    [System.Text.Encoding]::UTF8)
            try {
                return $reader.ReadToEnd() | ConvertFrom-Json
            } finally {
                $reader.Dispose()
            }
        } finally {
            $gzipStream.Dispose()
        }
    } finally {
        $inputStream.Dispose()
    }
}

function Get-Sha256Hex {
    param([string]$Path)

    $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($stream)
            $builder = [System.Text.StringBuilder]::new($hashBytes.Length * 2)
            foreach ($byte in $hashBytes) {
                [void]$builder.Append($byte.ToString("x2"))
            }
            return $builder.ToString()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Test-ManifestSignature {
    param(
        [string]$PublicKeyPath,
        [string]$ManifestPath,
        [string]$SignaturePath
    )

    $signatureText = Get-Content -LiteralPath $SignaturePath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($signatureText)) { throw "Signature Base64 vide." }

    try {
        $signatureBytes = [Convert]::FromBase64String($signatureText.Trim())
    } catch {
        throw "Signature Base64 invalide."
    }
    if ($signatureBytes.Length -le 0) { throw "Signature decodee vide." }

    $temp = Join-Path $env:TEMP ("official-update-verify-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    $javaFile = Join-Path $temp "VerifyManifestSignature.java"

    try {
        @'
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class VerifyManifestSignature {
    public static void main(String[] args) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.US_ASCII)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
        byte[] manifest = Files.readAllBytes(Paths.get(args[1]));
        byte[] signatureBytes = Base64.getDecoder().decode(new String(Files.readAllBytes(Paths.get(args[2])), StandardCharsets.UTF_8).trim());
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(key);
        signature.update(manifest);
        if (!signature.verify(signatureBytes)) {
            throw new IllegalStateException("Signature invalide");
        }
    }
}
'@ | Set-Content -LiteralPath $javaFile -Encoding ASCII

        $javac = "C:\Program Files\Android\Android Studio\jbr\bin\javac.exe"
        $java = "C:\Program Files\Android\Android Studio\jbr\bin\java.exe"
        if (-not (Test-Path -LiteralPath $javac)) { $javac = "javac" }
        if (-not (Test-Path -LiteralPath $java)) { $java = "java" }
        & $javac -encoding UTF-8 -d $temp $javaFile
        if ($LASTEXITCODE -ne 0) { throw "Compilation du verificateur de signature echouee." }
        & $java -cp $temp VerifyManifestSignature $PublicKeyPath $ManifestPath $SignaturePath
        if ($LASTEXITCODE -ne 0) { throw "Signature invalide." }
    } finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    Test-ManifestSignature `
            -PublicKeyPath $PublicKey `
            -ManifestPath $Manifest `
            -SignaturePath $Signature
    Write-Output "Signature ECDSA: OK"
} catch {
    Add-Error $_.Exception.Message
}

try {
    $manifestJson = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    throw "Manifeste JSON invalide: $($_.Exception.Message)"
}

if ($manifestJson.schemaVersion -ne 1) {
    Add-Error "schemaVersion invalide."
}
if ($null -eq $manifestJson.datasets) {
    Add-Error "Objet datasets absent."
}

$datasetEntries = @()
if ($null -ne $manifestJson.datasets) {
    $datasetEntries = @($manifestJson.datasets.PSObject.Properties)
}
if ($datasetEntries.Count -eq 0) {
    Add-Error "Aucun dataset dans le manifeste."
}

$validatedCount = 0
foreach ($property in $datasetEntries) {
    $datasetId = [string]$property.Name
    $entry = $property.Value
    $datasetErrorsBefore = $errors.Count

    if ([string]::IsNullOrWhiteSpace($datasetId)) {
        Add-Error "datasetId absent dans le manifeste."
        continue
    }
    if ($null -eq $entry) {
        Add-Error "${datasetId}: entree absente."
        continue
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry.url)) {
        Add-Error "${datasetId}: URL absente."
    } elseif (-not ([string]$entry.url).StartsWith("https://")) {
        Add-Error "${datasetId}: URL non HTTPS."
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry.version)) {
        Add-Error "${datasetId}: version absente."
    } elseif ($entry.version -notmatch '^\d{4}-\d{2}-\d{2}$') {
        Add-Error "${datasetId}: version invalide."
    }

    $datasetType = [string]$entry.type
    if ([string]::IsNullOrWhiteSpace($datasetType)) {
        $datasetType = "rules"
    }
    $isOfficialNumbers = $datasetType -eq "official_numbers"

    if ($isOfficialNumbers) {
        if ($datasetId -ne "official_numbers_fr") {
            Add-Error "${datasetId}: type official_numbers reserve a official_numbers_fr."
        }
        if ([string]$entry.compression -ne "gzip") {
            Add-Error "${datasetId}: compression gzip absente."
        }
        if ($null -eq $entry.entryCount) {
            Add-Error "${datasetId}: entryCount absent."
        } elseif ($entry.entryCount -le 0) {
            Add-Error "${datasetId}: entryCount invalide."
        }
    } else {
        if ($datasetType -ne "rules") {
            Add-Error "${datasetId}: type inconnu."
        }
        if ($null -eq $entry.ruleCount) {
            Add-Error "${datasetId}: ruleCount absent."
        } elseif ($entry.ruleCount -lt 0 -or $entry.ruleCount -gt 5000) {
            Add-Error "${datasetId}: ruleCount invalide."
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$entry.sha256)) {
        Add-Error "${datasetId}: SHA-256 absent."
    } elseif ($entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        Add-Error "${datasetId}: SHA-256 invalide."
    }

    $fileName = Get-DatasetFileName $entry.url
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        Add-Error "${datasetId}: nom de fichier introuvable depuis l'URL."
        continue
    }

    $datasetPath = Join-Path $PublicDatasetsDir $fileName
    if (-not (Test-Path -LiteralPath $datasetPath)) {
        Add-Error "${datasetId}: fichier dataset absent ($fileName)."
        continue
    }

    $actualSha = Get-Sha256Hex -Path $datasetPath
    if ($actualSha -ne ([string]$entry.sha256).ToLowerInvariant()) {
        Add-Error "${datasetId}: SHA-256 incoherent."
    }

    try {
        $datasetJson = if ($isOfficialNumbers) {
            if (-not $fileName.EndsWith(".json.gz")) {
                Add-Error "${datasetId}: extension .json.gz attendue."
            }
            Read-GzipJson -Path $datasetPath
        } else {
            Get-Content -LiteralPath $datasetPath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
    } catch {
        Add-Error "${datasetId}: JSON invalide."
        continue
    }

    if ($datasetJson.datasetId -ne $datasetId) {
        Add-Error "${datasetId}: datasetId incoherent dans le JSON."
    }
    if ($datasetJson.datasetVersion -ne $entry.version) {
        Add-Error "${datasetId}: datasetVersion incoherente."
    }

    if ($isOfficialNumbers) {
        if ($null -eq $datasetJson.entries) {
            Add-Error "${datasetId}: entries absent."
        } else {
            $entries = @($datasetJson.entries)
            if ($entries.Count -ne $entry.entryCount) {
                Add-Error "${datasetId}: entryCount incoherent."
            }
            if ($datasetJson.entryCount -ne $entry.entryCount) {
                Add-Error "${datasetId}: entryCount JSON incoherent."
            }
            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($item in $entries) {
                $number = [string]$item.n
                if ([string]::IsNullOrWhiteSpace($number)) {
                    Add-Error "${datasetId}: normalizedNumber absent."
                    break
                }
                if (-not $seen.Add($number)) {
                    Add-Error "${datasetId}: normalizedNumber duplique ($number)."
                    break
                }
                if ([string]::IsNullOrWhiteSpace([string]$item.d)) {
                    Add-Error "${datasetId}: displayName absent."
                    break
                }
            }
        }
    } else {
        $rules = @($datasetJson.rules)
        if ($null -eq $datasetJson.rules) {
            Add-Error "${datasetId}: rules absent."
        } elseif ($rules.Count -ne $entry.ruleCount) {
            Add-Error "${datasetId}: nombre de regles incoherent."
        }
    }

    if ($errors.Count -eq $datasetErrorsBefore) {
        $validatedCount++
        if ($isOfficialNumbers) {
            Write-Output "Dataset valide: $datasetId ($($entry.entryCount) numeros officiels)"
        } else {
            Write-Output "Dataset valide: $datasetId ($($rules.Count) regles)"
        }
    }
}

Write-Output "Datasets valides: $validatedCount / $($datasetEntries.Count)"

if ($errors.Count -gt 0) {
    throw "verify_update: $($errors.Count) erreur(s)."
}

Write-Output "verify_update: OK"
