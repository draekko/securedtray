package com.draekko.securetray;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.draekko.securedtray.ISecuredTrayListener;
import com.draekko.securedtray.SecuredTray;

import net.grandcentrix.tray.TrayPreferences;

public class MainActivity extends AppCompatActivity
    implements ISecuredTrayListener {

    public static final String TAG = "MainActivity";
    public static final String DEFAULT_KEY = "default_key";
    public static final String DEFAULT_TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

    public static final int CUSTOM_TRAY_VERSION = 1;
    public static final String CUSTOM_TRAY_NAME = "custom_tray_module";
    public static final String CUSTOM_TRAY_KEY = "custom_tray_key";
    public static final String CUSTOM_TRAY_TEXT = "Praesent porttitor consectetur leo at placerat.";

    public static final String CUSTOM_PASSWORD = "custom_pw";
    public static final String CUSTOM_PASSWORD_KEY = "custom_pw_key";
    public static final String CUSTOM_PASSWORD_TEXT = "Sed ut libero sed neque hendrerit pharetra vel eu libero.";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        LinearLayout ll = (LinearLayout)findViewById(R.id.main);

        SecuredTray securedTrayDefault = new SecuredTray(this);
        securedTrayDefault.setString(DEFAULT_KEY, DEFAULT_TEXT);
        String text1 = securedTrayDefault.getString(DEFAULT_KEY, "empty");

        SecuredTray securedTrayDefaultPw = new SecuredTray(this, CUSTOM_PASSWORD);
        securedTrayDefaultPw.setString(CUSTOM_PASSWORD_KEY, CUSTOM_PASSWORD_TEXT);
        String text2 = securedTrayDefaultPw.getString(CUSTOM_PASSWORD_KEY, "empty");

        TrayPreferences customTrayPreferences =
                new TrayPreferences(this, CUSTOM_TRAY_NAME, CUSTOM_TRAY_VERSION) {
            @Override
            protected void onCreate(int i) {
                // do your magic here
                Log.i(TAG, "CREATE VERSION:" + i);
            }

            @Override
            protected void onUpgrade(int i, int i1) {
                // do your magic here
                Log.i(TAG, "UPGRADE VERSION:" + i1);
            }

            @Override
            protected void onDowngrade(int i, int i1) {
                // do your magic here
                Log.i(TAG, "DOWNGRADE VERSION:" + i1);
            }
        };
        SecuredTray customSecuredTrayPw = new SecuredTray(this, customTrayPreferences, CUSTOM_PASSWORD);
        customSecuredTrayPw.setString(CUSTOM_TRAY_KEY, CUSTOM_TRAY_TEXT);
        String text3 = customSecuredTrayPw.getString(CUSTOM_TRAY_KEY, "empty");

        TextView tv1a = new TextView(this);
        tv1a.setText("Saved: " + DEFAULT_TEXT);
        ll.addView(tv1a);
        TextView tv1b = new TextView(this);
        tv1b.setText("Loaded: " + text1);
        ll.addView(tv1b);

        TextView tv2a = new TextView(this);
        tv2a.setText("Saved: " + CUSTOM_PASSWORD_TEXT);
        ll.addView(tv2a);
        TextView tv2b = new TextView(this);
        tv2b.setText("Loaded: " + text2);
        ll.addView(tv2b);

        TextView tv3a = new TextView(this);
        tv3a.setText("Saved: " + CUSTOM_TRAY_TEXT);
        ll.addView(tv3a);
        TextView tv3b = new TextView(this);
        tv3b.setText("Loaded: " + text3);
        ll.addView(tv3b);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            finish();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onCreation(int initialVersion) {
        // do your magic here
        if (initialVersion == 1) {
            Log.i(TAG, "CREATE VERSION:" + initialVersion);
        }
    }

    @Override
    public void onDowngrade(int oldVersion, int newVersion) {
        // do your magic here
        if (newVersion == 1) {
            Log.i(TAG, "UPGRADE VERSION:" + newVersion);
        }
    }

    @Override
    public void onUpgrade(int oldVersion, int newVersion) {
        // do your magic here
        if (newVersion == 1) {
            Log.i(TAG, "DOWNGRADE VERSION:" + newVersion);
        }
    }
}
