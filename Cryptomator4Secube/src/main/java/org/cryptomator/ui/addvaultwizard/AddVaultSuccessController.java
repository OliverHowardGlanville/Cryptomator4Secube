package org.cryptomator.ui.addvaultwizard;

import org.cryptomator.common.vaults.Vault;
import org.cryptomator.ui.common.FxController;
import org.cryptomator.ui.fxapp.FxApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.stage.Stage;
import java.util.Optional;

@AddVaultWizardScoped
public class AddVaultSuccessController implements FxController {

	private final FxApplication fxApplication;
	private final Stage window;
	private final ReadOnlyObjectProperty<Vault> vault;
	//private final String prova;
	
	private static final Logger LOG = LoggerFactory.getLogger(CreateNewVaultPasswordController.class);

	@Inject
	AddVaultSuccessController(FxApplication fxApplication, @AddVaultWizardWindow Stage window, @AddVaultWizardWindow ObjectProperty<Vault> vault) {
		this.fxApplication = fxApplication;
		this.window = window;
		this.vault = vault;
		//this.prova = "prova-string";

	}
	
	
	@FXML
	public void unlockAndClose() {
		close();
		fxApplication.startUnlockWorkflow(vault.get(), Optional.of(window));
	}

	@FXML
	public void close() {
		window.close();
	}

	/* Observables */

	public ReadOnlyObjectProperty<Vault> vaultProperty() {
		return vault;
	}

	public Vault getVault() {
		return vault.get();
	}
}
