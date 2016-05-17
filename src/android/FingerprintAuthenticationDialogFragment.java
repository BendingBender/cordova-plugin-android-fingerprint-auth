/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.DialogFragment;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import javax.crypto.Cipher;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back
 * to password authentication if fingerprint is not available.
 */
@TargetApi(23)
public class FingerprintAuthenticationDialogFragment extends DialogFragment
        implements FingerprintUiHelper.Callback {

    private Button mCancelButton;
    private View mFingerprintContent;

    private Stage mStage = Stage.FINGERPRINT;

    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintUiHelper mFingerprintUiHelper;
    FingerprintUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;

    private final int mCipherMode;
    private final String mDescription;

    public FingerprintAuthenticationDialogFragment(int cipherMode, String description) {
        this.mCipherMode = cipherMode;
        this.mDescription = description;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);

        mFingerprintUiHelperBuilder = new FingerprintUiHelper.FingerprintUiHelperBuilder(
                getContext(), getContext().getSystemService(FingerprintManager.class));

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        int fingerprint_auth_dialog_title_id = getResources()
                .getIdentifier("fingerprint_auth_dialog_title", "string",
                        FingerprintAuth.PACKAGE_NAME);
        getDialog().setTitle(getString(fingerprint_auth_dialog_title_id));
        int fingerprint_dialog_container_id = getResources()
                .getIdentifier("fingerprint_dialog_container", "layout",
                        FingerprintAuth.PACKAGE_NAME);
        View v = inflater.inflate(fingerprint_dialog_container_id, container, false);
        int cancel_button_id = getResources()
                .getIdentifier("cancel_button", "id", FingerprintAuth.PACKAGE_NAME);
        mCancelButton = (Button) v.findViewById(cancel_button_id);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                onCancel();
            }
        });

        int fingerprint_description_id = getResources()
                .getIdentifier("fingerprint_description", "id", FingerprintAuth.PACKAGE_NAME);
        TextView mFingerprintDescription = (TextView) v.findViewById(fingerprint_description_id);
        mFingerprintDescription.setText(this.mDescription);

        int fingerprint_container_id = getResources()
                .getIdentifier("fingerprint_container", "id", FingerprintAuth.PACKAGE_NAME);
        mFingerprintContent = v.findViewById(fingerprint_container_id);

        int fingerprint_icon_id = getResources()
                .getIdentifier("fingerprint_icon", "id", FingerprintAuth.PACKAGE_NAME);
        int fingerprint_status_id = getResources()
                .getIdentifier("fingerprint_status", "id", FingerprintAuth.PACKAGE_NAME);
        mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                (ImageView) v.findViewById(fingerprint_icon_id),
                (TextView) v.findViewById(fingerprint_status_id), this);
        updateStage();

        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mStage == Stage.FINGERPRINT) {
            mFingerprintUiHelper.startListening(mCryptoObject);
        }
    }

    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
        mFingerprintUiHelper.stopListening();
    }

    /**
     * Sets the crypto object to be passed in when authenticating with
     * fingerprint.
     */
    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    private void updateStage() {
        int cancel_id = getResources()
                .getIdentifier("cancel", "string", FingerprintAuth.PACKAGE_NAME);
        switch (mStage) {
            case FINGERPRINT:
                mCancelButton.setText(cancel_id);
                mFingerprintContent.setVisibility(View.VISIBLE);
                break;
            case NEW_FINGERPRINT_ENROLLED:
                // Intentional fall through
        }
    }

    @Override
    public void onAuthenticated() {
        switch (this.mCipherMode) {
            case Cipher.ENCRYPT_MODE:
                FingerprintAuth.onAuthenticatedEncrypt();
                break;
            case Cipher.DECRYPT_MODE:
                FingerprintAuth.onAuthenticatedDecrypt();
                break;
        }
        dismiss();
    }

    @Override
    public void onError() {
    }

    public void onCancel() {
        FingerprintAuth.onCancel();
        dismiss();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to
     * authenticate with.
     */
    public enum Stage {
        FINGERPRINT,
        NEW_FINGERPRINT_ENROLLED
    }
}
