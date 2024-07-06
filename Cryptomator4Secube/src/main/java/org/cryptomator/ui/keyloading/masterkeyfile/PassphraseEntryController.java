package org.cryptomator.ui.keyloading.masterkeyfile;

import org.cryptomator.common.Nullable;
import org.cryptomator.common.keychain.KeychainManager;
import org.cryptomator.common.vaults.Vault;
import org.cryptomator.secube.Communication;
import org.cryptomator.ui.common.ErrorComponent;
import org.cryptomator.ui.common.FxController;
import org.cryptomator.common.Passphrase;
import org.cryptomator.ui.common.WeakBindings;
import org.cryptomator.ui.controls.FormattedLabel;
import org.cryptomator.ui.controls.NiceSecurePasswordField;
import org.cryptomator.ui.forgetPassword.ForgetPasswordComponent;
import org.cryptomator.ui.keyloading.KeyLoading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.BaseEncoding;

import javax.inject.Inject;
import javax.inject.Named;
import javafx.animation.Animation;
import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.beans.binding.ObjectBinding;
import javafx.beans.binding.StringBinding;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.ReadOnlyBooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.ComboBox;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import javafx.scene.transform.Rotate;
import javafx.scene.transform.Translate;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.util.Duration;

import javafx.scene.control.Button;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;

@PassphraseEntryScoped
public class PassphraseEntryController implements FxController {

	private static final Logger LOG = LoggerFactory.getLogger(PassphraseEntryController.class);

	private final Stage window;
	private final Vault vault;
	private final CompletableFuture<PassphraseEntryResult> result;
	private final Passphrase savedPassword;
	private final ForgetPasswordComponent.Builder forgetPassword;
	private final KeychainManager keychain;
	private final StringBinding vaultName;
	private final BooleanProperty unlockInProgress = new SimpleBooleanProperty();
	private final ObjectBinding<ContentDisplay> unlockButtonContentDisplay = Bindings.createObjectBinding(this::getUnlockButtonContentDisplay, unlockInProgress);
	private final BooleanProperty unlockButtonDisabled = new SimpleBooleanProperty();
	private final BooleanProperty unlockButtonSecubeVisible = new SimpleBooleanProperty();
	private final BooleanProperty unlockButtonVisible = new SimpleBooleanProperty();
	public boolean visibleListEmpty;

	/* FXML */
	public NiceSecurePasswordField passwordField;
	public String serialNumberChoosen;
	public NiceSecurePasswordField PIN;
	public ComboBox<String> secubeSerialList;
	public CheckBox savePasswordCheckbox;
	public ImageView face;
	public ImageView leftArm;
	public ImageView rightArm;
	public ImageView legs;
	public ImageView body;
	public Animation unlockAnimation;
	public FormattedLabel labelPIN;
	public FormattedLabel labelList;
	public FormattedLabel noSEcubeFound;
	public VBox normalWindow;
	public VBox enterPasswordField;
	public Button unlockButton;

	@Inject
	public PassphraseEntryController(@KeyLoading Stage window, @KeyLoading Vault vault, CompletableFuture<PassphraseEntryResult> result, @Nullable @Named("savedPassword") Passphrase savedPassword, ForgetPasswordComponent.Builder forgetPassword, KeychainManager keychain) {
		this.window = window;
		this.vault = vault;
		this.result = result;
		this.savedPassword = savedPassword;
		this.forgetPassword = forgetPassword;
		this.keychain = keychain;
		this.vaultName = WeakBindings.bindString(vault.displayNameProperty());
		window.setOnHiding(this::windowClosed);
		result.whenCompleteAsync((r, t) -> unlockInProgress.set(false), Platform::runLater);
	}

	@FXML
	public void initialize() throws IOException {
		if (vault.getVaultSettings().getVaultsecube()) {
			this.unlockButtonSecubeVisible.set(true);
			this.unlockButtonVisible.set(false);
			this.enterPasswordField.setVisible(false);

		} else {
			this.unlockButtonVisible.set(true);
			this.unlockButtonSecubeVisible.set(false);
			this.enterPasswordField.setVisible(true);

		}
		
		LOG.debug("sono entrato in initialize, password: " + savedPassword);
		
		if (savedPassword != null) {
			savePasswordCheckbox.setSelected(true);
			passwordField.setPassword(savedPassword);
		}
				
		unlockButtonDisabled.bind(unlockInProgress.or(passwordField.textProperty().isEmpty()));

		var leftArmTranslation = new Translate(24, 0);
		var leftArmRotation = new Rotate(60, 16, 30, 0);
		var leftArmRetracted = new KeyValue(leftArmTranslation.xProperty(), 24);
		var leftArmExtended = new KeyValue(leftArmTranslation.xProperty(), 0.0);
		var leftArmHorizontal = new KeyValue(leftArmRotation.angleProperty(), 60, Interpolator.EASE_OUT);
		var leftArmHanging = new KeyValue(leftArmRotation.angleProperty(), 0);
		leftArm.getTransforms().setAll(leftArmTranslation, leftArmRotation);

		var rightArmTranslation = new Translate(-24, 0);
		var rightArmRotation = new Rotate(60, 48, 30, 0);
		var rightArmRetracted = new KeyValue(rightArmTranslation.xProperty(), -24);
		var rightArmExtended = new KeyValue(rightArmTranslation.xProperty(), 0.0);
		var rightArmHorizontal = new KeyValue(rightArmRotation.angleProperty(), -60);
		var rightArmHanging = new KeyValue(rightArmRotation.angleProperty(), 0, Interpolator.EASE_OUT);
		rightArm.getTransforms().setAll(rightArmTranslation, rightArmRotation);

		var legsRetractedY = new KeyValue(legs.scaleYProperty(), 0);
		var legsExtendedY = new KeyValue(legs.scaleYProperty(), 1, Interpolator.EASE_OUT);
		var legsRetractedX = new KeyValue(legs.scaleXProperty(), 0);
		var legsExtendedX = new KeyValue(legs.scaleXProperty(), 1, Interpolator.EASE_OUT);
		legs.setScaleY(0);
		legs.setScaleX(0);

		var faceHidden = new KeyValue(face.opacityProperty(), 0.0);
		var faceVisible = new KeyValue(face.opacityProperty(), 1.0, Interpolator.LINEAR);
		face.setOpacity(0);

		unlockAnimation = new Timeline( //
				new KeyFrame(Duration.ZERO, leftArmRetracted, leftArmHorizontal, rightArmRetracted, rightArmHorizontal, legsRetractedY, legsRetractedX, faceHidden), //
				new KeyFrame(Duration.millis(200), leftArmExtended, leftArmHorizontal, rightArmRetracted, rightArmHorizontal), //
				new KeyFrame(Duration.millis(400), leftArmExtended, leftArmHanging, rightArmExtended, rightArmHorizontal), //
				new KeyFrame(Duration.millis(600), leftArmExtended, leftArmHanging, rightArmExtended, rightArmHanging), //
				new KeyFrame(Duration.millis(800), legsExtendedY, legsExtendedX, faceHidden), //
				new KeyFrame(Duration.millis(1000), faceVisible) //
		);

		result.whenCompleteAsync((r, t) -> stopUnlockAnimation());
		
		// SEcube list (if so)
		try {
			ObservableList<String> serialNumberList = FXCollections.observableArrayList();
			String cmd = "../dist/win/secube_listing.exe";
			InputStream stdin = Runtime.getRuntime().exec(cmd).getInputStream();
			InputStreamReader isr = new InputStreamReader(stdin);
			BufferedReader br = new BufferedReader(isr);
			//StringBuilder sb = new StringBuilder();
			String s1;
			while ((s1 = br.readLine()) != null) {
				//sb.append(s1);
				serialNumberList.add(s1);
			}
			CharSequence errorSeq = "Error : ";
			if (serialNumberList.toString().contains(errorSeq)) {
				 //throw new IOException("Failed getting password. " + serialNumberList.toString());
//				secubeSerialList.setVisible(false);
//				PIN.setVisible(false);
//				labelPIN.setVisible(false);
//				labelList.setVisible(false);
				noSEcubeFound.setVisible(true);
				normalWindow.setVisible(false);
				unlockButton.disableProperty().set(true);
			} else {
				secubeSerialList.setItems(serialNumberList);	
				secubeSerialList.setOnAction(this::onComboBoxSelected);
				//secubeSerialList.setVisible(true);
				noSEcubeFound.setVisible(false);
			}
			
		} catch (IOException e) {
			throw new IOException("Failed getting password", e);
		}
	}
	
	private void onComboBoxSelected(ActionEvent event) {
        this.serialNumberChoosen = secubeSerialList.getSelectionModel().getSelectedItem();
    }

	@FXML
	public void cancel() {
		window.close();
	}

	private void windowClosed(WindowEvent windowEvent) {
		if(!result.isDone()) {
			result.cancel(true);
			LOG.debug("Unlock canceled by user.");
		}

	}

	@FXML
	public void unlock() {
		LOG.debug("UnlockController.unlock(), saved passwrod"+ savedPassword);
		
		unlockInProgress.set(true);
		CharSequence pwFieldContents = passwordField.getCharacters();
		Passphrase pw = Passphrase.copyOf(pwFieldContents);
		LOG.debug("Write password: "+ savedPassword);

		result.complete(new PassphraseEntryResult(pw, savePasswordCheckbox.isSelected()));

		startUnlockAnimation();
	}
	
	@FXML
	public void unlocksecube() throws Exception {
		
		/* Here a request should be sent to the secube with the vault ID 
		 * and the SEcube will send back the password to unlock the vault. 
		 */
		
		LOG.trace("UnlockController.unlock() secube");
		unlockInProgress.set(true);
		
		try {
			// Convert the IDVault to an ID compatible with SECube, between 1 and 999
			byte[] randomBytes = new byte[9];
			randomBytes = BaseEncoding.base64Url().decode(this.vault.getId());
			int randomNumber = ((randomBytes[0] & 0xFF) << 8) | (randomBytes[1] & 0xFF);
	        String SECubeVaultID = Integer.toString(1 + (randomNumber % 999));
			
			String key = Communication.main("retrieve-key", serialNumberChoosen, PIN.getCharacters().toString(), SECubeVaultID);
			
			Passphrase pw = Passphrase.copyOf(key);
			
			result.complete(new PassphraseEntryResult(pw, savePasswordCheckbox.isSelected()));
			
			startUnlockAnimation();
			
			if(key.contains("Error:")) {
				throw new IOException("Failed initialize vault. " + key);
			}
		} catch (IOException e) {
			throw new IOException("Failed getting password", e);
		}
	}
	

	private void startUnlockAnimation() {
		leftArm.setVisible(true);
		rightArm.setVisible(true);
		legs.setVisible(true);
		face.setVisible(true);
		unlockAnimation.playFromStart();
	}

	private void stopUnlockAnimation() {
		unlockAnimation.stop();
		leftArm.setVisible(false);
		rightArm.setVisible(false);
		legs.setVisible(false);
		face.setVisible(false);
	}

	/* Save Password */

	@FXML
	private void didClickSavePasswordCheckbox() {
		if (!savePasswordCheckbox.isSelected() && savedPassword != null) {
			forgetPassword.vault(vault).owner(window).build().showForgetPassword().thenAccept(forgotten -> savePasswordCheckbox.setSelected(!forgotten));
		}
	}

	/* Getter/Setter */

	public String getVaultName() {
		return vaultName.get();
	}

	public StringBinding vaultNameProperty() {
		return vaultName;
	}

	public ObjectBinding<ContentDisplay> unlockButtonContentDisplayProperty() {
		return unlockButtonContentDisplay;
	}

	public ContentDisplay getUnlockButtonContentDisplay() {
		return unlockInProgress.get() ? ContentDisplay.LEFT : ContentDisplay.TEXT_ONLY;
	}

	public ReadOnlyBooleanProperty userInteractionDisabledProperty() {
		return unlockInProgress;
	}

	public boolean isUserInteractionDisabled() {
		return unlockInProgress.get();
	}

	public ReadOnlyBooleanProperty unlockButtonDisabledProperty() {
		return unlockButtonDisabled;
	}

	public boolean isUnlockButtonDisabled() {
		return unlockButtonDisabled.get();
	}
	
	
	
	public ReadOnlyBooleanProperty unlockButtonSecubeVisibleProperty() {
		return  unlockButtonSecubeVisible;
	}

	public boolean isUnlockButtonSecubeVisible() {
		return unlockButtonSecubeVisible.get();
	}
	
	public ReadOnlyBooleanProperty unlockButtonVisibleProperty() {
		return  unlockButtonVisible;
	}

	public boolean isUnlockButtonVisible() {
		return unlockButtonVisible.get();
	}

	public boolean isKeychainAccessAvailable() {
		return keychain.isSupported();
	}


}
