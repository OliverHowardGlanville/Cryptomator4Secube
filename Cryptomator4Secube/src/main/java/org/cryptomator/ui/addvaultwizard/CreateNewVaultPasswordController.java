package org.cryptomator.ui.addvaultwizard;

import dagger.Lazy;

import org.cryptomator.common.settings.VaultSettings;
import org.cryptomator.common.vaults.Vault;
import org.cryptomator.common.vaults.VaultListManager;
import org.cryptomator.common.vaults.VaultState.Value;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;
import org.cryptomator.secube.Communication;
import org.cryptomator.ui.common.ErrorComponent;
import org.cryptomator.ui.common.FxController;
import org.cryptomator.ui.common.FxmlFile;
import org.cryptomator.ui.common.FxmlScene;
import org.cryptomator.ui.common.NewPasswordController;
import org.cryptomator.ui.common.Tasks;
import org.cryptomator.ui.controls.NiceSecurePasswordField;
import org.cryptomator.ui.keyloading.masterkeyfile.MasterkeyFileLoadingStrategy;
import org.cryptomator.ui.recoverykey.RecoveryKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.BaseEncoding;

import javax.inject.Inject;
import javax.inject.Named;
import javafx.beans.binding.Bindings;
import javafx.beans.binding.ObjectBinding;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.channels.WritableByteChannel;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.cryptomator.common.Constants.MASTERKEY_FILENAME;

@AddVaultWizardScoped
public class CreateNewVaultPasswordController implements FxController {

	private static final Logger LOG = LoggerFactory.getLogger(CreateNewVaultPasswordController.class);
	private static final URI DEFAULT_KEY_ID = URI.create(MasterkeyFileLoadingStrategy.SCHEME + ":" + MASTERKEY_FILENAME); // TODO better place?

	private final Stage window;
	private final Lazy<Scene> chooseLocationScene;
	private final Lazy<Scene> recoveryKeyScene;
	private final Lazy<Scene> successScene;
	private final ErrorComponent.Builder errorComponent;
	private final ExecutorService executor;
	private final RecoveryKeyFactory recoveryKeyFactory;
	private final StringProperty vaultNameProperty;
	private final ObjectProperty<Path> vaultPathProperty;
	private final ObjectProperty<Vault> vaultProperty;
	private final StringProperty recoveryKeyProperty;
	private final VaultListManager vaultListManager;
	private final ResourceBundle resourceBundle;
	private final ReadmeGenerator readmeGenerator;
	private final SecureRandom csprng;
	private final MasterkeyFileAccess masterkeyFileAccess;
	private final BooleanProperty processing;
	private final BooleanProperty readyToCreateVault;
	private final ObjectBinding<ContentDisplay> createVaultButtonState;
	
	private static final Random RNG = new Random();
	
	
	private final String vaultId = generateId();

	/* FXML */
	public ToggleGroup recoveryKeyChoice;
	public Toggle showRecoveryKey;
	public Toggle skipRecoveryKey;
	public NewPasswordController newPasswordSceneController;
	public String serialNumberChoosen;
	public ComboBox<String> secubeSerialList;
	public NiceSecurePasswordField PIN;
	public boolean visibleListEmpty;
	public Label labelPIN;
	public Label labelList;
	public Label noSEcubeFound;
	public Button createSEcubeButton;


	@Inject
	CreateNewVaultPasswordController(@AddVaultWizardWindow Stage window, @FxmlScene(FxmlFile.ADDVAULT_NEW_LOCATION) Lazy<Scene> chooseLocationScene, @FxmlScene(FxmlFile.ADDVAULT_NEW_RECOVERYKEY) Lazy<Scene> recoveryKeyScene, @FxmlScene(FxmlFile.ADDVAULT_SUCCESS) Lazy<Scene> successScene, ErrorComponent.Builder errorComponent, ExecutorService executor, RecoveryKeyFactory recoveryKeyFactory, @Named("vaultName") StringProperty vaultName, ObjectProperty<Path> vaultPath, @AddVaultWizardWindow ObjectProperty<Vault> vault, @Named("recoveryKey") StringProperty recoveryKey, VaultListManager vaultListManager, ResourceBundle resourceBundle, ReadmeGenerator readmeGenerator, SecureRandom csprng, MasterkeyFileAccess masterkeyFileAccess) {
		this.window = window;
		this.chooseLocationScene = chooseLocationScene;
		this.recoveryKeyScene = recoveryKeyScene;
		this.successScene = successScene;
		this.errorComponent = errorComponent;
		this.executor = executor;
		this.recoveryKeyFactory = recoveryKeyFactory;
		this.vaultNameProperty = vaultName;
		this.vaultPathProperty = vaultPath;
		this.vaultProperty = vault;
		this.recoveryKeyProperty = recoveryKey;
		this.vaultListManager = vaultListManager;
		this.resourceBundle = resourceBundle;
		this.readmeGenerator = readmeGenerator;
		this.csprng = csprng;
		this.masterkeyFileAccess = masterkeyFileAccess;
		this.processing = new SimpleBooleanProperty();
		this.readyToCreateVault = new SimpleBooleanProperty();
		this.createVaultButtonState = Bindings.createObjectBinding(this::getCreateVaultButtonState, processing);

	}

	@FXML
	public void initialize() throws IOException {
		readyToCreateVault.bind(newPasswordSceneController.goodPasswordProperty().and(recoveryKeyChoice.selectedToggleProperty().isNotNull()).and(processing.not()));
		window.setOnHiding(event -> {
			newPasswordSceneController.passwordField.wipe();
			newPasswordSceneController.reenterField.wipe();
		});
				
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
				secubeSerialList.setVisible(false);
				PIN.setVisible(false);
				labelPIN.setVisible(false);
				labelList.setVisible(false);
				noSEcubeFound.setVisible(true);
				createSEcubeButton.disableProperty().set(true);
			} else {
				secubeSerialList.setItems(serialNumberList);	
				secubeSerialList.setOnAction(this::onComboBoxSelected);
				secubeSerialList.setVisible(true);
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
	public void back() {
		window.setScene(chooseLocationScene.get());
	}

	@FXML
	public void next() {
		Path pathToVault = vaultPathProperty.get();

		try {
			Files.createDirectory(pathToVault);
		} catch (IOException e) {
			LOG.error("Failed to create vault directory.", e);
			errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
			return;
		}

		if (showRecoveryKey.equals(recoveryKeyChoice.getSelectedToggle())) {
			showRecoveryKeyScene();
		} else if (skipRecoveryKey.equals(recoveryKeyChoice.getSelectedToggle())) {
			showSuccessScene();
		} else {
			throw new IllegalStateException("Unexpected toggle state");
		}
	}

	private void showRecoveryKeyScene() {
		Path pathToVault = vaultPathProperty.get();
		processing.set(true);
		Tasks.create(() -> {
			initializeVault(pathToVault);
			return recoveryKeyFactory.createRecoveryKey(pathToVault, newPasswordSceneController.passwordField.getCharacters());
		}).onSuccess(recoveryKey -> {
			initializationSucceeded(pathToVault);
			recoveryKeyProperty.set(recoveryKey);
			window.setScene(recoveryKeyScene.get());
		}).onError(IOException.class, e -> {
			LOG.error("Failed to initialize vault.", e);
			errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
		}).andFinally(() -> {
			processing.set(false);
		}).runOnce(executor);
	}

	private void showSuccessScene() {
		Path pathToVault = vaultPathProperty.get();
		processing.set(true);
		Tasks.create(() -> {
			initializeVault(pathToVault);
		}).onSuccess(() -> {
			initializationSucceeded(pathToVault);
			window.setScene(successScene.get());
		}).onError(IOException.class, e -> {
			LOG.error("Failed to initialize vault.", e);
			errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
		}).andFinally(() -> {
			processing.set(false);
		}).runOnce(executor);
	}

	private void initializeVault(Path path) throws IOException {
		// 1. write masterkey:
		Path masterkeyFilePath = path.resolve(MASTERKEY_FILENAME);
		try (Masterkey masterkey = Masterkey.generate(csprng)) {
			
			
			
			masterkeyFileAccess.persist(masterkey, masterkeyFilePath, newPasswordSceneController.passwordField.getCharacters());

			// 2. initialize vault:
			try {
				MasterkeyLoader loader = ignored -> masterkey.copy();
				CryptoFileSystemProperties fsProps = CryptoFileSystemProperties.cryptoFileSystemProperties().withCipherCombo(CryptorProvider.Scheme.SIV_CTRMAC).withKeyLoader(loader).build();
				CryptoFileSystemProvider.initialize(path, fsProps, DEFAULT_KEY_ID);

				// 3. write vault-internal readme file:
				String vaultReadmeFileName = resourceBundle.getString("addvault.new.readme.accessLocation.fileName");
				try (FileSystem fs = CryptoFileSystemProvider.newFileSystem(path, fsProps); //
					 WritableByteChannel ch = Files.newByteChannel(fs.getPath("/", vaultReadmeFileName), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
					ch.write(US_ASCII.encode(readmeGenerator.createVaultAccessLocationReadmeRtf()));
				}
			} catch (CryptoException e) {
				throw new IOException("Failed initialize vault.", e);
			}
		}

		// 4. write vault-external readme file:
		String storagePathReadmeFileName = resourceBundle.getString("addvault.new.readme.storageLocation.fileName");
		try (WritableByteChannel ch = Files.newByteChannel(path.resolve(storagePathReadmeFileName), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			ch.write(US_ASCII.encode(readmeGenerator.createVaultStorageLocationReadmeRtf()));
		}
		

		LOG.info("Created vault at {}", path);
	}

	private void initializationSucceeded(Path pathToVault) {
		try {
			Vault newVault = vaultListManager.add(pathToVault);
			LOG.info("Initialization succeded point");
			vaultProperty.set(newVault);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}
	
	
/////////////////////////////////////////////////////////////////
//////////////////SEcube //////////////////////////////////////
////////////////////////////////////////////////////////////////

	/* When the user click on create secure password, the duplicated function of SEcube are called in this order:
	 * 1) createPasswordSecube
	 * 2) showSuccessSceneSEcube
	 * 3) initializeVaultSecube
	 * 4) initializationSucceededSEcube
	 * In the forth function is called addSEcube function, 
	 * that will create and initialize the Vault, returned by the function.
	 *
	 * In the function initializeVaultSecube, call the function to send the Vault ID  
	 * to the SEcube.
	 *  Then the SEcube will generate and store the password. 
	 * */
	
	private void initializeVaultSecube(Path path) throws Exception {
		// 1. write masterkey:
		Path masterkeyFilePath = path.resolve(MASTERKEY_FILENAME);
		try (Masterkey masterkey = Masterkey.generate(csprng)) {
			
			/*Call SEcube -> create password*/
			
			// Convert the IDVault to an ID compatible with SECube, between 1 and 999
			byte[] randomBytes = new byte[9];
			randomBytes = BaseEncoding.base64Url().decode(this.vaultId);
			int randomNumber = ((randomBytes[0] & 0xFF) << 8) | (randomBytes[1] & 0xFF);
	        String SECubeVaultID = Integer.toString(1 + (randomNumber % 999));

			
			String key;
			key = Communication.main("create-key", serialNumberChoosen, PIN.getCharacters().toString(), SECubeVaultID);
			if(key.contains("Error:")) {
				Exception e = new IOException("Failed initialize vault. " + key);
				errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
				throw e;
			}
			
			masterkeyFileAccess.persist(masterkey, masterkeyFilePath, key);

			// 2. initialize vault:
			try {
				MasterkeyLoader loader = ignored -> masterkey.copy();
				CryptoFileSystemProperties fsProps = CryptoFileSystemProperties.cryptoFileSystemProperties().withCipherCombo(CryptorProvider.Scheme.SIV_CTRMAC).withKeyLoader(loader).build();
				CryptoFileSystemProvider.initialize(path, fsProps, DEFAULT_KEY_ID);

				// 3. write vault-internal readme file:
				String vaultReadmeFileName = resourceBundle.getString("addvault.new.readme.accessLocation.fileName");
				try (FileSystem fs = CryptoFileSystemProvider.newFileSystem(path, fsProps); //
					 WritableByteChannel ch = Files.newByteChannel(fs.getPath("/", vaultReadmeFileName), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
					ch.write(US_ASCII.encode(readmeGenerator.createVaultAccessLocationReadmeRtf()));
				}
			} catch (CryptoException e) {
				throw new IOException("Failed initialize vault.", e);
			}
		}

		// 4. write vault-external readme file:
		String storagePathReadmeFileName = resourceBundle.getString("addvault.new.readme.storageLocation.fileName");
		try (WritableByteChannel ch = Files.newByteChannel(path.resolve(storagePathReadmeFileName), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
			ch.write(US_ASCII.encode(readmeGenerator.createVaultStorageLocationReadmeRtf()));
		}
		

		LOG.info("Created vault at {}", path);
	}
	
	/*
	 * Specific function initialising the vault created with SEcube using the vault ID
	 */
	private void initializationSucceededSEcube(Path pathToVault) {
		try {
			Vault newVault = vaultListManager.addSEcube(pathToVault, vaultId);
			LOG.info("Initialization succeded point");
			vaultProperty.set(newVault);
			
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}
	
	private String generateId() {
		byte[] randomBytes = new byte[9];
		RNG.nextBytes(randomBytes);
		return BaseEncoding.base64Url().encode(randomBytes);
	}
	
	
	private void showSuccessSceneSEcube() {
		Path pathToVault = vaultPathProperty.get();
		processing.set(true);
		Tasks.create(() -> {
			initializeVaultSecube(pathToVault);
		}).onSuccess(() -> {
			/* SEcube duplicated function */
			initializationSucceededSEcube(pathToVault);
			window.setScene(successScene.get());
		}).onError(IOException.class, e -> {
			LOG.error("Failed to initialize vault.", e);
			errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
		}).andFinally(() -> {
			processing.set(false);
		}).runOnce(executor);
	}
	
	@FXML
	private boolean createPasswordSEcube() {
		Path pathToVault = vaultPathProperty.get();

		try {
			Files.createDirectory(pathToVault);
		} catch (IOException e) {
			LOG.error("Failed to create vault directory.", e);
			errorComponent.cause(e).window(window).returnToScene(window.getScene()).build().showErrorScene();
			return false;
	}
		/* SEcube duplicated function */
		showSuccessSceneSEcube();

		return true;
	}



//////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

	/* Getter/Setter */

	public String getVaultName() {
		return vaultNameProperty.get();
	}

	public StringProperty vaultNameProperty() {
		return vaultNameProperty;
	}

	public BooleanProperty readyToCreateVaultProperty() {
		return readyToCreateVault;
	}

	public boolean isReadyToCreateVault() {
		return readyToCreateVault.get();
	}

	public ObjectBinding<ContentDisplay> createVaultButtonStateProperty() {
		return createVaultButtonState;
	}

	public ContentDisplay getCreateVaultButtonState() {
		return processing.get() ? ContentDisplay.LEFT : ContentDisplay.TEXT_ONLY;
	}
}
