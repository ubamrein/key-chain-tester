package com.ubique.attestationlab;

import android.app.Activity;
import android.content.ClipData;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.text.InputType;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public final class MainActivity extends Activity {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String PREFS = "attestation_lab";
    private static final String PREF_LAST_ALIAS = "last_alias";
    private static final Pattern VALID_ALIAS = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private EditText aliasInput;
    private EditText challengeInput;
    private CheckBox strongBoxOption;
    private CheckBox unlockedDeviceOption;
    private CheckBox userAuthenticationOption;
    private CheckBox devicePropertiesOption;
    private Button generateButton;
    private Button loadButton;
    private Button shareButton;
    private TextView statusView;
    private List<X509Certificate> certificateChain = new ArrayList<>();
    private boolean busy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        String savedAlias = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(PREF_LAST_ALIAS, "p256_attested_key");
        aliasInput.setText(savedAlias);
        challengeInput.setText(createRandomChallenge());
        setStatus("Create a key to retrieve its certificate chain. The private key stays in Android Keystore.");
        updateButtons();
    }

    @Override
    protected void onDestroy() {
        executor.shutdown();
        super.onDestroy();
    }

    private void buildUi() {
        int padding = dp(20);
        ScrollView scrollView = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        scrollView.addView(content);
        setContentView(scrollView);

        TextView title = new TextView(this);
        title.setText("Key Attestation Lab");
        title.setTextSize(26);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        content.addView(title, matchWrap());

        TextView intro = new TextView(this);
        intro.setText("Create a P-256 ECDSA key in Android Keystore, inspect the certificates Android returns, and share the chain as a PEM file.");
        intro.setTextSize(15);
        intro.setPadding(0, dp(8), 0, dp(16));
        content.addView(intro, matchWrap());

        addLabel(content, "Key alias");
        aliasInput = new EditText(this);
        aliasInput.setSingleLine(true);
        aliasInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        aliasInput.setHint("p256_attested_key");
        content.addView(aliasInput, matchWrap());

        addLabel(content, "Attestation challenge (hex, 1–128 bytes)");
        challengeInput = new EditText(this);
        challengeInput.setSingleLine(true);
        challengeInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        challengeInput.setHint("A fresh random challenge is generated for you");
        content.addView(challengeInput, matchWrap());

        TextView flagsLabel = new TextView(this);
        flagsLabel.setText("Key options");
        flagsLabel.setTextSize(18);
        flagsLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        flagsLabel.setPadding(0, dp(20), 0, dp(4));
        content.addView(flagsLabel, matchWrap());

        strongBoxOption = addOption(content,
                "Create in StrongBox (Android 9+)",
                "Uses the dedicated secure element when the device supports it.");
        unlockedDeviceOption = addOption(content,
                "Require the device to be unlocked (Android 9+)",
                "The private key cannot be used while the device is locked.");
        userAuthenticationOption = addOption(content,
                "Require user authentication to use the key",
                "Applies when the key is used for signing; this app does not sign data.");
        devicePropertiesOption = addOption(content,
                "Include device properties in attestation (Android 12+)",
                "Shares device details with anyone who receives the certificate chain.");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            setUnsupported(strongBoxOption);
            setUnsupported(unlockedDeviceOption);
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            setUnsupported(devicePropertiesOption);
        }

        generateButton = new Button(this);
        generateButton.setText("Create P-256 key and get chain");
        generateButton.setOnClickListener(view -> createKey());
        LinearLayout.LayoutParams buttonParams = matchWrap();
        buttonParams.topMargin = dp(14);
        content.addView(generateButton, buttonParams);

        loadButton = new Button(this);
        loadButton.setText("Load chain for this alias");
        loadButton.setOnClickListener(view -> loadChain());
        content.addView(loadButton, matchWrap());

        shareButton = new Button(this);
        shareButton.setText("Share certificate chain as PEM");
        shareButton.setOnClickListener(view -> sharePem());
        content.addView(shareButton, matchWrap());

        statusView = new TextView(this);
        statusView.setTextSize(14);
        statusView.setTextIsSelectable(true);
        statusView.setPadding(0, dp(14), 0, dp(20));
        content.addView(statusView, matchWrap());
    }

    private CheckBox addOption(LinearLayout parent, String title, String summary) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(7), 0, dp(7));

        CheckBox checkBox = new CheckBox(this);
        checkBox.setText(title);
        checkBox.setTextSize(15);
        row.addView(checkBox, matchWrap());

        TextView description = new TextView(this);
        description.setText(summary);
        description.setTextSize(13);
        description.setPadding(dp(36), 0, 0, 0);
        row.addView(description, matchWrap());
        parent.addView(row, matchWrap());
        return checkBox;
    }

    private void setUnsupported(CheckBox checkBox) {
        checkBox.setEnabled(false);
        checkBox.setText(checkBox.getText() + " — not supported on this Android version");
    }

    private void addLabel(LinearLayout parent, String text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(14);
        label.setPadding(0, dp(8), 0, 0);
        parent.addView(label, matchWrap());
    }

    private void createKey() {
        final String alias = aliasInput.getText().toString().trim();
        final byte[] challenge;
        try {
            if (!VALID_ALIAS.matcher(alias).matches()) {
                throw new IllegalArgumentException("Use an alias of 1–64 letters, numbers, dots, underscores, or hyphens.");
            }
            challenge = parseChallenge(challengeInput.getText().toString());
        } catch (IllegalArgumentException e) {
            setStatus(e.getMessage());
            return;
        }

        final boolean useStrongBox = strongBoxOption.isChecked();
        final boolean requireUnlocked = unlockedDeviceOption.isChecked();
        final boolean requireAuthentication = userAuthenticationOption.isChecked();
        final boolean includeDeviceProperties = devicePropertiesOption.isChecked();

        busy = true;
        updateButtons();
        setStatus("Creating the key and reading the returned certificate chain…");
        executor.execute(() -> {
            try {
                KeyStore keyStore = loadAndroidKeyStore();
                if (keyStore.containsAlias(alias)) {
                    throw new IllegalArgumentException("That alias already exists. Choose another alias to avoid replacing an existing key.");
                }

                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                        alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .setUserAuthenticationRequired(requireAuthentication);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(useStrongBox);
                    builder.setUnlockedDeviceRequired(requireUnlocked);
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    builder.setDevicePropertiesAttestationIncluded(includeDeviceProperties);
                }

                KeyPairGenerator generator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                generator.initialize(builder.build());
                generator.generateKeyPair();

                List<X509Certificate> chain = readChain(loadAndroidKeyStore(), alias);
                runOnUiThread(() -> {
                    certificateChain = chain;
                    getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(PREF_LAST_ALIAS, alias).apply();
                    aliasInput.setText(alias);
                    busy = false;
                    updateButtons();
                    setStatus(chainSummary(alias, chain) + "\n\nIf StrongBox was requested, key creation succeeds only when this device provides it.");
                });
            } catch (StrongBoxUnavailableException e) {
                showFailure("StrongBox is unavailable on this device. Turn off the StrongBox option and try again.");
            } catch (IllegalArgumentException e) {
                showFailure(e.getMessage());
            } catch (Exception e) {
                showFailure("Key creation failed: " + readableMessage(e));
            }
        });
    }

    private void loadChain() {
        final String alias = aliasInput.getText().toString().trim();
        if (!VALID_ALIAS.matcher(alias).matches()) {
            setStatus("Enter a valid key alias first.");
            return;
        }
        busy = true;
        updateButtons();
        setStatus("Loading the certificate chain from Android Keystore…");
        executor.execute(() -> {
            try {
                List<X509Certificate> chain = readChain(loadAndroidKeyStore(), alias);
                runOnUiThread(() -> {
                    certificateChain = chain;
                    busy = false;
                    updateButtons();
                    setStatus(chainSummary(alias, chain));
                });
            } catch (Exception e) {
                showFailure("Could not load a certificate chain for this alias: " + readableMessage(e));
            }
        });
    }

    private void sharePem() {
        if (certificateChain.isEmpty()) {
            setStatus("Create or load a certificate chain first.");
            return;
        }
        try {
            String safeAlias = aliasInput.getText().toString().trim().replaceAll("[^A-Za-z0-9._-]", "_");
            if (safeAlias.isEmpty()) safeAlias = "p256_key";
            if (!safeAlias.matches("[A-Za-z0-9_-].*")) safeAlias = "key_" + safeAlias;
            String fileName = safeAlias + "_attestation_chain.pem";
            File directory = new File(getCacheDir(), "attestation_exports");
            if (!directory.exists() && !directory.mkdirs()) {
                throw new IllegalStateException("Could not create the temporary export folder.");
            }
            File pemFile = new File(directory, fileName);
            try (FileOutputStream output = new FileOutputStream(pemFile, false)) {
                output.write(toPem(certificateChain).getBytes(StandardCharsets.US_ASCII));
            }

            Uri uri = PemFileProvider.uriFor(this, fileName);
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("application/x-pem-file");
            send.putExtra(Intent.EXTRA_STREAM, uri);
            send.putExtra(Intent.EXTRA_SUBJECT, "Key attestation certificate chain");
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            send.setClipData(ClipData.newUri(getContentResolver(), "PEM certificate chain", uri));
            startActivity(Intent.createChooser(send, "Share certificate chain"));
        } catch (Exception e) {
            setStatus("Could not share the PEM file: " + readableMessage(e));
        }
    }

    private List<X509Certificate> readChain(KeyStore keyStore, String alias) throws Exception {
        Certificate[] certificates = keyStore.getCertificateChain(alias);
        if (certificates == null || certificates.length == 0) {
            throw new IllegalStateException("Android Keystore returned no certificates for this key.");
        }
        List<X509Certificate> result = new ArrayList<>(certificates.length);
        for (Certificate certificate : certificates) {
            if (!(certificate instanceof X509Certificate)) {
                throw new IllegalStateException("Android Keystore returned a non-X.509 certificate.");
            }
            result.add((X509Certificate) certificate);
        }
        return result;
    }

    private KeyStore loadAndroidKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore;
    }

    private String toPem(List<X509Certificate> chain) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate certificate : chain) {
            pem.append("-----BEGIN CERTIFICATE-----\n");
            String encoded = android.util.Base64.encodeToString(certificate.getEncoded(), android.util.Base64.NO_WRAP);
            for (int start = 0; start < encoded.length(); start += 64) {
                pem.append(encoded, start, Math.min(start + 64, encoded.length())).append('\n');
            }
            pem.append("-----END CERTIFICATE-----\n");
        }
        return pem.toString();
    }

    private byte[] parseChallenge(String input) {
        String hex = input.replaceAll("\\s", "");
        if (hex.isEmpty()) {
            throw new IllegalArgumentException("Enter a non-empty hexadecimal attestation challenge.");
        }
        if ((hex.length() & 1) != 0 || hex.length() > 256 || !hex.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("The challenge must be valid hex representing 1–128 bytes.");
        }
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private String createRandomChallenge() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
        return hex.toString();
    }

    private String chainSummary(String alias, List<X509Certificate> chain) {
        StringBuilder summary = new StringBuilder("Alias: ").append(alias)
                .append("\nCertificates returned: ").append(chain.size());
        if (chain.size() == 1) {
            summary.append("\nThis device returned only one certificate; hardware attestation may not be available.");
        }
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            summary.append("\n\n").append(i == 0 ? "Leaf" : "Chain certificate ").append(i == 0 ? "" : i)
                    .append("\nSubject: ").append(certificate.getSubjectX500Principal().getName())
                    .append("\nIssuer: ").append(certificate.getIssuerX500Principal().getName());
        }
        return summary.toString();
    }

    private String readableMessage(Exception error) {
        String message = error.getMessage();
        if (message != null && !message.trim().isEmpty()) return message;
        Throwable cause = error.getCause();
        return cause != null && cause.getMessage() != null ? cause.getMessage() : error.getClass().getSimpleName();
    }

    private void showFailure(String message) {
        runOnUiThread(() -> {
            busy = false;
            updateButtons();
            setStatus(message == null ? "The operation failed." : message);
        });
    }

    private void updateButtons() {
        if (generateButton == null) return;
        generateButton.setEnabled(!busy);
        loadButton.setEnabled(!busy);
        shareButton.setEnabled(!busy && !certificateChain.isEmpty());
    }

    private void setStatus(String message) {
        statusView.setText(message);
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
