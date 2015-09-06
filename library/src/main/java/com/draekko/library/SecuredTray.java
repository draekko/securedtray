/*
 * Copyright 2015 Benoit Touchette
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Wrapper class which adds a layer of encryption to the persistent storage
 * and retrieval of sensitive key-value pairs of primitive data types.
 *
 * This class provides important but nevertheless imperfect protection against
 * attacks by casual snoopers. It is crucial to remember that even encrypted
 * data may still be susceptible to attacks, especially on rooted devices.
 */

package com.draekko.library;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Base64;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import net.grandcentrix.tray.TrayModulePreferences;
import net.grandcentrix.tray.migration.Migration;
import net.grandcentrix.tray.provider.TrayItem;
import net.grandcentrix.tray.storage.ModularizedStorage;
import net.grandcentrix.tray.storage.PreferenceStorage;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;

//===========================================================
//Class
//===========================================================

public class SecuredTray {

    // ===========================================================
    // Constants
    // ===========================================================

    private static final String TAG = "SecuredTray";
    private static final String DEFAULT_MODULE_NAME = "DefaultModule";

    // ===========================================================
    // Fields
    // ===========================================================

    private static Context context;
    private AesCbcWithIntegrity.SecretKeys secretKeys;
    private TrayModulePreferences trayModulePreferences;
    private SecuredTray securedTray;
    private static List<ISecuredTrayListener> listeners;

    // ===========================================================
    // Constructors
    // ===========================================================

    /**
     * SecuredTray constructor
     * @param context
     */
    public SecuredTray(Context context) {
        this(context,  null, null, null, null, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param allTrayModulePreferences
     */
    public SecuredTray(Context context,
                       final TrayModulePreferences allTrayModulePreferences) {
        this(context, null, allTrayModulePreferences, null, null, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param secretKey
     * @param allTrayModulePreferences
     */
    public SecuredTray(Context context,
                       final AesCbcWithIntegrity.SecretKeys secretKey,
                       final TrayModulePreferences allTrayModulePreferences) {
        this(context, secretKey, allTrayModulePreferences, null, null, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param allTrayModulePreferences
     * @param password
     */
    public SecuredTray(Context context,
                       final TrayModulePreferences allTrayModulePreferences,
                       final String password) {
        this(context, null, allTrayModulePreferences, null, password, 1);
    }


    /**
     * SecuredTray constructor
     * @param context
     * @param moduleName
     */
    public SecuredTray(Context context,
                       final String moduleName) {
        this(context, null, null, moduleName, null, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param secretKey
     * @param moduleName
     */
    public SecuredTray(Context context,
                       final AesCbcWithIntegrity.SecretKeys secretKey,
                       final String moduleName) {
        this(context, secretKey, null, moduleName, null, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param moduleName
     * @param password
     */
    public SecuredTray(Context context,
                       final String moduleName,
                       final String password) {
        this(context, null, null, moduleName, password, 1);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param version
     */
    public SecuredTray(Context context, final int version) {
        this(context, null,  null,  null,  null, version);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param allTrayModulePreferences
     * @param version
     */
    public SecuredTray(Context context,
                       final TrayModulePreferences allTrayModulePreferences,
                       final int version) {
        this(context, null, allTrayModulePreferences, null, null, version);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param secretKey
     * @param allTrayModulePreferences
     * @param version
     */
    public SecuredTray(Context context,
                       final AesCbcWithIntegrity.SecretKeys secretKey,
                       final TrayModulePreferences allTrayModulePreferences,
                       final int version) {
        this(context, secretKey, allTrayModulePreferences, null, null, version);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param allTrayModulePreferences
     * @param password
     * @param version
     */
    public SecuredTray(Context context,
                       final TrayModulePreferences allTrayModulePreferences,
                       final String password,
                       final int version) {
        this(context, null, allTrayModulePreferences, null, password, version);
    }


    /**
     * SecuredTray constructor
     * @param context
     * @param moduleName
     * @param version
     */
    public SecuredTray(Context context,
                       final String moduleName,
                       final int version) {
        this(context, null, null, moduleName, null, version);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param secretKey
     * @param moduleName
     * @param version
     */
    public SecuredTray(Context context,
                       final AesCbcWithIntegrity.SecretKeys secretKey,
                       final String moduleName,
                       final int version) {
        this(context, secretKey, null, moduleName, null, version);
    }

    /**
     * SecuredTray constructor
     * @param context
     * @param moduleName
     * @param password
     * @param version
     */
    public SecuredTray(Context context,
                       final String moduleName,
                       final String password,
                       final int version) {
        this(context, null, null, moduleName, password, version);
    }

    // ===========================================================

    /**
     * SecuredTray private constructor
     * @param local_context
     * @param secretKey
     * @param allTrayModulePreferences
     * @param moduleName
     * @param password
     * @param version
     */
    private SecuredTray(Context local_context,
                        final AesCbcWithIntegrity.SecretKeys secretKey,
                        final TrayModulePreferences allTrayModulePreferences,
                        final String moduleName,
                        final String password,
                        final int version) {
        if (local_context == null) {
            throw  new InvalidParameterException("context == null");
        } else {
            context = local_context;
        }

        listeners = new ArrayList<ISecuredTrayListener>();

        if (allTrayModulePreferences != null) {
            this.trayModulePreferences = allTrayModulePreferences;
        } else if (moduleName != null) {
            this.trayModulePreferences = new DefaultModulePreference(context, moduleName, version);
        } else {
            this.trayModulePreferences = new DefaultModulePreference(context, version);
        }

        if (secretKey != null) {
            secretKeys = secretKey;
        } else if (password == null || TextUtils.isEmpty(password)) {
            try {
                String key = generateAesKeyName(context);
                String keyAsString = this.trayModulePreferences.getString(key, null);
                if (keyAsString == null) {
                    secretKeys = AesCbcWithIntegrity.generateKey();
                    this.trayModulePreferences.put(key, secretKeys.toString());
                }else{
                    secretKeys = AesCbcWithIntegrity.keys(keyAsString);
                }
                if(secretKeys == null){
                    throw new GeneralSecurityException("Problem generating Key");
                }
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                throw new IllegalStateException(e);
            }
        }else{
            try {
                if(password == null || password.isEmpty()){
                    throw new InvalidParameterException("Password is null or empty");
                }
                secretKeys = AesCbcWithIntegrity.generateKeyFromPassword(password, getDeviceSerialNumber(context));
                if(secretKeys == null){
                    throw new GeneralSecurityException("Problem generating Key From Password");
                }
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                throw new IllegalStateException(e);
            }
        }
    }

    // ===========================================================
    // Private Members
    // ===========================================================

    /**
     * generateAesKeyName
     * @param context
     * @return
     * @throws GeneralSecurityException
     */
    private static String generateAesKeyName(Context context)
            throws GeneralSecurityException {
        final String password = context.getPackageName();
        final byte[] salt = getDeviceSerialNumber(context).getBytes();
        AesCbcWithIntegrity.SecretKeys generatedKeyName =
                AesCbcWithIntegrity.generateKeyFromPassword(password, salt);
        if(generatedKeyName == null){
            throw new GeneralSecurityException("Key not generated");
        }

        return hashPrefKey(generatedKeyName.toString());
    }

    /**
     * hashPrefKey
     * @param prefKey
     * @return
     */
    private static String hashPrefKey(String prefKey)  {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = prefKey.getBytes("UTF-8");
            digest.update(bytes, 0, bytes.length);

            return Base64.encodeToString(digest.digest(), AesCbcWithIntegrity.BASE64_FLAGS);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getDeviceSerialNumber
     * @param context
     * @return
     */
    private static String getDeviceSerialNumber(Context context) {
        try {
            String deviceSerial = (String) Build.class.getField("SERIAL").get(null);
            if (TextUtils.isEmpty(deviceSerial)) {
                deviceSerial = Settings.Secure.getString(
                    context.getContentResolver(),
                    Settings.Secure.ANDROID_ID);
            }
            return deviceSerial;
        } catch (Exception e) {
            return Settings.Secure.getString(
                    context.getContentResolver(),
                    Settings.Secure.ANDROID_ID);
        }
    }

    /**
     * encrypt
     * @param cleartext
     * @return
     */
    private String encrypt(String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext;
        }
        try {
            return AesCbcWithIntegrity.encrypt(cleartext, secretKeys).toString();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * decrypt
     * @param ciphertext
     * @return
     */
    private String decrypt(final String ciphertext) {
        if (TextUtils.isEmpty(ciphertext)) {
            return ciphertext;
        }
        try {
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac =
                    new AesCbcWithIntegrity.CipherTextIvMac(ciphertext);
            return AesCbcWithIntegrity.decryptString(cipherTextIvMac, secretKeys);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * getSecuredTrayListeners()
     * @return
     */
    protected static List<ISecuredTrayListener> getSecuredTrayListeners() {
        return getListeners(ISecuredTrayListener.class);
    }

    /**
     * getListeners
     * @param listenerInterface
     * @param <T>
     * @return
     */
    @SuppressWarnings("unchecked")
    protected static <T> List<T> getListeners(Class<T> listenerInterface) {
        List<T> listeners = new ArrayList<T>(2);
        if (context != null && listenerInterface.isAssignableFrom(context.getClass())) {
            listeners.add((T) context);
        }
        return Collections.unmodifiableList(listeners);
    }

    /**
     * onCreation
     * @param initialVersion
     */
    protected static void private_onCreation(int initialVersion) {
        for (ISecuredTrayListener listener : getSecuredTrayListeners()) {
            listener.onCreation(initialVersion);
        }
        for (ISecuredTrayListener listener : listeners) {
            listener.onCreation(initialVersion);
        }
    }

    /**
     * onUpgrade
     * @param oldVersion
     * @param newVersion
     */
    protected static void private_onUpgrade(final int oldVersion, final int newVersion) {
        for (ISecuredTrayListener listener : getSecuredTrayListeners()) {
            listener.onUpgrade(oldVersion, newVersion);
        }
        for (ISecuredTrayListener listener : listeners) {
            listener.onUpgrade(oldVersion, newVersion);
        }
    }

    /**
     * onDowngrade
     * @param oldVersion
     * @param newVersion
     */
    protected static void private_onDowngrade(final int oldVersion, final int newVersion) {
        for (ISecuredTrayListener listener : getSecuredTrayListeners()) {
            listener.onDowngrade(oldVersion, newVersion);
        }
        for (ISecuredTrayListener listener : listeners) {
            listener.onDowngrade(oldVersion, newVersion);
        }
    }

    // ===========================================================
    // Public Members
    // ===========================================================

    /**
     * add
     * @param iSecuredTrayListener
     */
    public synchronized void addListener(ISecuredTrayListener iSecuredTrayListener) {
        listeners.add(iSecuredTrayListener);
    }

    /**
     * remove
     * @param iSecuredTrayListener
     */
    public synchronized void removeListener(ISecuredTrayListener iSecuredTrayListener) {
        listeners.remove(iSecuredTrayListener);
    }

    /**
     * removeModule
     */
    public void removeModule() {
        trayModulePreferences.remove(DEFAULT_MODULE_NAME);
    }

    /**
     * removeModule
     * @param moduleName
     */
    public void removeModule(String moduleName) {
        trayModulePreferences.remove(moduleName);
    }

    /**
     * clear
     */
    public void clear() {
        trayModulePreferences.clear();
    }

    /**
     * migrate
     * @param migration
     */
    public void migrate(Migration<TrayItem> migration) {
        trayModulePreferences.migrate(migration);
    }

    /**
     * getStorage
     * @return
     */
    public PreferenceStorage<TrayItem> getStorage() {
        return trayModulePreferences.getStorage();
    }

    /**
     * getPref
     * @param name
     * @return
     */
    public TrayItem getPref(String name) {
        return trayModulePreferences.getPref(name);
    }

    /**
     * getModularizedStorage
     * @return
     */
    public ModularizedStorage<TrayItem> getModularizedStorage() {
        return trayModulePreferences.getModularizedStorage();
    }

    /**
     * getAll
     * @return
     */
    public Collection<TrayItem> getAll() {
        return trayModulePreferences.getAll();
    }

    /**
     * generatePassword
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateRandomPassword() throws NoSuchAlgorithmException{
        final SecureRandom random = new SecureRandom();
        final KeyGenerator generator = KeyGenerator.getInstance("AES");
        try {
            generator.init(256, random);
        } catch (Exception e) {
            try {
                generator.init(192, random);
            } catch (Exception e1) {
                generator.init(128, random);
            }
        }
        return Base64.encodeToString(generator.generateKey().getEncoded(), AesCbcWithIntegrity.BASE64_FLAGS);
    }

    /**
     * getModule
     * @return
     */
    public TrayModulePreferences getModule() {
        return trayModulePreferences;
    }

    /**
     * setModule
     * @param trayModulePreferences
     */
    public void setModule(TrayModulePreferences trayModulePreferences) {
        this.trayModulePreferences = trayModulePreferences;
    }

    /**
     * getBoolean
     * @param key
     * @return
     */
    public boolean getBoolean(String key) {
        boolean value = getBoolean(key, false);
        return value;
    }

    /**
     * getBoolean
     * @param key
     * @param value
     * @return
     */
    public boolean getBoolean(String key, boolean value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return Boolean.parseBoolean(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setBoolean
     * @param key
     * @param value
     */
    public void setBoolean(String key, boolean value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(Boolean.toString(value)));
    }

    /**
     * getString
     */
    public String getString(String key) {
        String value = getString(key, null);
        return value;
    }

    /**
     * getString
     * @param key
     * @param value
     * @return
     */
    public String getString(String key, String value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        return (encryptedValue != null) ? decrypt(encryptedValue) : value;
    }

    /**
     * setString
     * @param key
     * @param value
     */
    public void setString(String key, String value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(value));
    }

    /**
     * getInt
     * @param key
     * @return
     */
    public int getInt(String key) {
        int value = getInt(key, -1);
        return value;
    }

    /**
     * getInt
     * @param key
     * @param value
     * @return
     */
    public int getInt(String key, int value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return Integer.parseInt(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setInt
     * @param key
     * @param value
     */
    public void setInt(String key, int value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(Integer.toString(value)));
    }

    /**
     * getLong
     * @param key
     * @return
     */
    public long getLong(String key) {
        Long value = getLong(key, -1L);
        return value;
    }

    /**
     * getLong
     * @param key
     * @param value
     * @return
     */
    public long getLong(String key, long value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return Long.parseLong(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setLong
     * @param key
     * @param value
     */
    public void setLong(String key, long value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(Long.toString(value)));
    }

    /**
     * getFloat
     * @param key
     * @return
     */
    public float getFloat(String key) {
        Float value = getFloat(key, -1.0f);
        return value;
    }

    /**
     * getFloat
     * @param key
     * @param value
     * @return
     */
    public float getFloat(String key, float value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return Float.parseFloat(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setFloat
     * @param key
     * @param value
     */
    public void setFloat(String key, float value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(Float.toString(value)));
    }

    /**
     * getDouble
     * @param key
     * @return
     */
    public double getDouble(String key) {
        Double value = getDouble(key, -1.0);
        return value;
    }

    /**
     * getDouble
     * @param key
     * @param value
     * @return
     */
    public double getDouble(String key, double value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return Double.parseDouble(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setDouble
     * @param key
     * @param value
     */
    public void setDouble(String key, double value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(Double.toString(value)));
    }

    /**
     * getBigInteger
     * @param key
     * @return
     */
    public BigInteger getBigInteger(String key) {
        BigInteger value = getDouble(key, BigInteger.valueOf(-1));
        return value;
    }

    /**
     * getBigInteger
     * @param key
     * @param value
     * @return
     */
    public BigInteger getDouble(String key, BigInteger value) {
        final String encryptedValue = trayModulePreferences.getString(hashPrefKey(key), null);
        if (encryptedValue == null) {
            return value;
        }
        try {
            return new BigInteger(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    /**
     * setBigInteger
     * @param key
     * @param value
     */
    public void setBigInteger(String key, BigInteger value) {
        trayModulePreferences.put(hashPrefKey(key), encrypt(String.valueOf(value)));
    }

    // ===========================================================
    // Private Class
    // ===========================================================

    private class DefaultModulePreference extends TrayModulePreferences {

        /**
         * DefaultModulePreference constructor
         * @param context
         * @param version
         */
        public DefaultModulePreference(final Context context, final int version) {
            this(context, DEFAULT_MODULE_NAME, version);
        }

        /**
         * DefaultModulePreference constructor
         * @param context
         * @param moduleName
         * @param version
         */
        private DefaultModulePreference(final Context context, final String moduleName, final int version) {
            super(context, moduleName, version);
        }

        /**
         * onCreate
         * @param initialVersion the version set in the constructor, always > 0
         */
        @Override
        protected void onCreate(final int initialVersion) {
            private_onCreation(initialVersion);
        }

        /**
         * onUpgrade
         * @param oldVersion version before upgrade, always > 0
         * @param newVersion version after upgrade
         */
        @Override
        protected void onUpgrade(final int oldVersion, final int newVersion) {
            private_onUpgrade(oldVersion, newVersion);
        }

        /**
         * onDowngrade
         * @param oldVersion version before upgrade, always > 0
         * @param newVersion version after upgrade
         */
        @Override
        protected void onDowngrade(final int oldVersion, final int newVersion) {
            private_onDowngrade(oldVersion, newVersion);
        }
    }
}
