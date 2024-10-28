package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/kirsle/configdir"
	nativeDialog "github.com/sqweek/dialog" // alias to avoid conflict
)

var (
	appDataDir      string
	recentFilesPath string
	keyPath         string
	aesKey          []byte
	recentFiles     []string
	isDarkMode      bool    = false
	fontSize        float32 = 12.0
	autoSaveFlag    bool    = false
)

type Document struct {
	Path     string
	TextArea *widget.Entry
	Tab      *container.TabItem
}

var openDocuments = make(map[string]*Document) // Track open documents

func init() {
	appDataDir = configdir.LocalConfig("NotepadV")
	configdir.MakePath(appDataDir)

	// File paths for the recent files JSON and encryption key
	recentFilesPath = filepath.Join(appDataDir, "recent_files.json")
	keyPath = filepath.Join(appDataDir, "key.key")

	loadOrCreateKey() // Load encryption key or generate a new one
	loadRecentFiles() // Load recent files on startup
}

func loadOrCreateKey() {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		newKey := make([]byte, 32)
		if _, err := rand.Read(newKey); err != nil {
			fmt.Println("Failed to generate encryption key:", err)
			return
		}
		if err := ioutil.WriteFile(keyPath, newKey, 0600); err != nil {
			fmt.Println("Failed to save encryption key:", err)
			return
		}
		aesKey = newKey
	} else {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil || len(key) != 32 {
			fmt.Println("Failed to load encryption key:", err)
			return
		}
		aesKey = key
	}
}

func loadRecentFiles() {
	if data, err := ioutil.ReadFile(recentFilesPath); err == nil {
		json.Unmarshal(data, &recentFiles)
	}
}

func saveRecentFiles() {
	data, _ := json.Marshal(recentFiles)
	_ = ioutil.WriteFile(recentFilesPath, data, 0644)
}

func addToRecentFiles(filePath string) {
	// Add new file to the beginning and remove duplicates
	for i, path := range recentFiles {
		if path == filePath {
			recentFiles = append(recentFiles[:i], recentFiles[i+1:]...)
			break
		}
	}
	recentFiles = append([]string{filePath}, recentFiles...)

	// Limit recent files list to 15 entries
	if len(recentFiles) > 15 {
		recentFiles = recentFiles[:15]
	}
	saveRecentFiles()
}

func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

func openFile(win fyne.Window, tabs *container.AppTabs) {
	filePath, err := nativeDialog.File().Load() // using nativeDialog for native file open dialog
	if err != nil {
		dialog.ShowError(err, win)
		return
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		dialog.ShowError(err, win)
		return
	}

	if filepath.Ext(filePath) == ".gtxt" {
		data, err = decrypt(data)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to decrypt file"), win)
			return
		}
	}

	if _, exists := openDocuments[filePath]; exists {
		dialog.ShowInformation("Info", "Document is already open.", win)
		return
	}

	textArea := widget.NewMultiLineEntry()
	textArea.SetText(string(data))

	tab := container.NewTabItem(filepath.Base(filePath), textArea)
	tabs.Append(tab)
	tabs.Select(tab)

	// Store the document in open documents and add to recent files
	openDocuments[filePath] = &Document{Path: filePath, TextArea: textArea, Tab: tab}
	addToRecentFiles(filePath)
}

func saveFile(doc *Document, win fyne.Window) {
	autoSaveFlag = true

	data := []byte(doc.TextArea.Text)
	if filepath.Ext(doc.Path) == ".gtxt" {
		encData, err := encrypt(data)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to encrypt file"), win)
			return
		}
		data = encData
	}

	if err := ioutil.WriteFile(doc.Path, data, 0644); err != nil {
		dialog.ShowError(err, win)
	}
	addToRecentFiles(doc.Path)
}

func saveAsFile(doc *Document, win fyne.Window) {
	filePath, err := nativeDialog.File().Title("Save As").Save() // using nativeDialog for native file save dialog
	if err != nil {
		dialog.ShowError(err, win)
		return
	}

	if filepath.Ext(filePath) != ".gtxt" {
		filePath += ".gtxt"
	}

	doc.Path = filePath
	data := []byte(doc.TextArea.Text)
	encData, err := encrypt(data) // Encrypt the data before saving
	if err != nil {
		dialog.ShowError(err, win)
		return
	}

	if err := ioutil.WriteFile(doc.Path, encData, 0644); err != nil {
		dialog.ShowError(err, win)
		return
	}

	win.SetTitle(fmt.Sprintf("Notepad - %s", filePath))
	addToRecentFiles(filePath)
}

func newDocument(tabs *container.AppTabs) *Document {
	textArea := widget.NewMultiLineEntry()
	tab := container.NewTabItem("Untitled", textArea)
	tabs.Append(tab)
	tabs.Select(tab)

	doc := &Document{Path: "", TextArea: textArea, Tab: tab}
	openDocuments["Untitled"] = doc
	return doc
}

func main() {
	a := app.New()
	win := a.NewWindow("Notepad")
	win.Resize(fyne.NewSize(800, 600))
	win.SetMaster()

	tabs := container.NewAppTabs()
	menu := fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("New Document", func() { newDocument(tabs) }),
			fyne.NewMenuItem("Open", func() { openFile(win, tabs) }),
			fyne.NewMenuItem("Save", func() {
				if doc := openDocuments[tabs.Selected().Text]; doc != nil {
					saveFile(doc, win)
				}
			}),
			fyne.NewMenuItem("Save As", func() {
				if doc := openDocuments[tabs.Selected().Text]; doc != nil {
					saveAsFile(doc, win)
				}
			}),
		),
	)
	win.SetMainMenu(menu)
	win.SetContent(tabs)

	fmt.Println("Starting application...")
	win.ShowAndRun()
	fmt.Println("Application has exited.")
}
