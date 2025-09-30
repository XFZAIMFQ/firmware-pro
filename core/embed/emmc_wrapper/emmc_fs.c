#include "emmc_fs.h"
#include "debug_utils.h"

EMMC_WRAPPER_STATUS emmc_wrapper_status = {0};

PARTITION VolToPart[FF_VOLUMES] = {
    {0, 1}, // Onekey Data
    {0, 2}, // User Data
};

// misc
void emmc_fs_dbgex_set(const char *msg) {
  strncpy(emmc_wrapper_status.debug_extra, msg, 64);
}
void emmc_fs_dbgex_append(const char *msg) {
  strncat(emmc_wrapper_status.debug_extra, msg,
          64 - strlen(emmc_wrapper_status.debug_extra));
}
void emmc_fs_dbgex_clr() { memset(emmc_wrapper_status.debug_extra, '\0', 64); }
void emmc_fs_format_status(char *str, size_t str_len) {
  // clang-format off
    snprintf(
        str, str_len, 
        "\nis_inited=%s\nis_mounted_onekey_data=%s\nis_mounted_user_data=%s\nfrom_function=%s\nff_call=%s\nff_result=%x\ndebug_extra=%s\n",
        emmc_wrapper_status.is_inited?"True":"False",
        emmc_wrapper_status.is_mounted_onekey_data?"True":"False",
        emmc_wrapper_status.is_mounted_user_data?"True":"False",
        emmc_wrapper_status.from_function,
        emmc_wrapper_status.ff_call,
        emmc_wrapper_status.ff_result,
        emmc_wrapper_status.debug_extra
    );
  // clang-format on
}

// basic

bool emmc_fs_init() {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (emmc_wrapper_status.is_inited)
    return false;

  emmc_init();

  emmc_wrapper_status.is_inited = true;

  return true;
}

bool emmc_fs_uninit() {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  emmc_deinit();

  emmc_wrapper_status.is_inited = false;

  return true;
}

bool emmc_fs_recreate(bool partition_table, bool onekey_data, bool user_data) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  // reset status
  emmc_wrapper_status.is_mounted_onekey_data = false;
  emmc_wrapper_status.is_mounted_user_data = false;

  // partition table
  BYTE work[FF_MAX_SS];
  LBA_t plist[] = {
      BOOT_EMMC_BLOCKS,
      100}; // 1G sectors for 1st partition and left all for 2nd partition
  if (partition_table) {
    ExecuteCheck_OKEMMC_SIMPLE(f_fdisk(0, plist, work));
  }

  // filesystem
  MKFS_PARM mk_para = {
      .fmt = FM_FAT32,
  };
  if (partition_table || onekey_data) {
    ExecuteCheck_OKEMMC_SIMPLE(f_mkfs("0:", &mk_para, work, sizeof(work)));
    ExecuteCheck_OKEMMC_SIMPLE(
        f_mount(&emmc_wrapper_status.fs_obj_onekeyData, "0:", 1));

    // set label
    ExecuteCheck_OKEMMC_SIMPLE(f_setlabel("0:Onekey Data"));

    // create folders and files to avoid stuck in boardloader
    // this should be kept if we switch to use command to upload files
    // FIL res_flag;
    // ExecuteCheck_OKEMMC_SIMPLE(f_mkdir("0:res"));
    // ExecuteCheck_OKEMMC_SIMPLE(f_open(&res_flag, "0:res/.ONEKEY_RESOURCE",
    // FA_CREATE_NEW | FA_WRITE));
    // ExecuteCheck_OKEMMC_SIMPLE(f_close(&res_flag));
    // ExecuteCheck_OKEMMC_SIMPLE(f_mkdir("0:boot"));

    ExecuteCheck_OKEMMC_SIMPLE(f_unmount("0:"));
  }
  if (partition_table || user_data) {
    ExecuteCheck_OKEMMC_SIMPLE(f_mkfs("1:", &mk_para, work, sizeof(work)));
    ExecuteCheck_OKEMMC_SIMPLE(
        f_mount(&emmc_wrapper_status.fs_obj_userData, "1:", 1));

    ExecuteCheck_OKEMMC_SIMPLE(f_setlabel("1:User Data"));

    ExecuteCheck_OKEMMC_SIMPLE(f_unmount("1:"));
  }

  return true;
}

bool emmc_fs_is_partitioned() {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  // since there is no other ways, we check it by mount the partition
  FATFS fs_obj_test;
  ExecuteCheck_OKEMMC_SIMPLE(f_mount(&fs_obj_test, "0:", 1));
  ExecuteCheck_OKEMMC_SIMPLE(f_unmount("0:"));
  // ExecuteCheck_OKEMMC_SIMPLE(f_mount(&fs_obj_test, "1:", 1));
  // ExecuteCheck_OKEMMC_SIMPLE(f_unmount("1:"));
  return true;
}

bool emmc_fs_mount(bool onekey_data, bool user_data) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  if (onekey_data) {
    ExecuteCheck_OKEMMC_SIMPLE(
        f_mount(&emmc_wrapper_status.fs_obj_onekeyData, "0:", 1));
    emmc_wrapper_status.is_mounted_onekey_data = true;
  }
  if (user_data) {
    ExecuteCheck_OKEMMC_SIMPLE(
        f_mount(&emmc_wrapper_status.fs_obj_userData, "1:", 1));
    emmc_wrapper_status.is_mounted_user_data = true;
  }
  return true;
}

bool emmc_fs_unmount(bool onekey_data, bool user_data) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  if (onekey_data) {
    ExecuteCheck_OKEMMC_SIMPLE(f_unmount("0:"));
    emmc_wrapper_status.is_mounted_onekey_data = false;
  }
  if (user_data) {
    ExecuteCheck_OKEMMC_SIMPLE(f_unmount("1:"));
    emmc_wrapper_status.is_mounted_user_data = false;
  }
  return true;
}

FRESULT emmc_fs_f_stat(const TCHAR *path_buff, FILINFO *fno) {
  // this is the wrapper function that could handle root volume
  // f_stat will give error if you pass "0:" to it

  FRESULT fresult;

  // check if it's volume root
  if (':' == path_buff[strlen(path_buff) - 1]) {
    // wipe FILINFO to zero as f_stat won't work on root folder
    if (fno != NULL)
      memset(fno, 0x00, sizeof(FILINFO));
    // fill FILINFO by our own
    // copy over path
    memcpy(fno->fname, path_buff, 2);
    // root must be a directory
    fno->fattrib |= AM_DIR;
    // root must exist, return true
    fresult = FR_OK;
  } else {
    // non root case, do the actual check
    fresult = f_stat(path_buff, fno);
  }

  strncpy(emmc_wrapper_status.ff_call,
          "emmc_fs_f_stat(const TCHAR* path_buff, FILINFO* fno)", 128);
  emmc_wrapper_status.ff_result = fresult;
  return fresult;
}

bool emmc_fs_path_type(const char *path, PathType *path_type) {
  FILINFO file_info;
  FRESULT res = f_stat(path, &file_info);
  if (res != FR_OK) {
    return false;
  }
  if (path_type == NULL) {
    return true;
  }
  if (file_info.fattrib & AM_DIR) {
    *path_type = PATH_DIR;
  } else {
    *path_type = PATH_FILE;
  }
  return true;
}

bool emmc_fs_path_exist(const char *path_buff) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  return (emmc_fs_f_stat(path_buff, NULL) == FR_OK);
}

// please note, this function returns true even the path not exist
// use file_info->path_exist instead
bool emmc_fs_path_info(const char *path_buff, EMMC_PATH_INFO *file_info) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  // get info
  FILINFO finfo;
  switch (emmc_fs_f_stat(path_buff, &finfo)) {
  case FR_NO_FILE:
  case FR_NO_PATH:
    file_info->path_exist = false;
    return true;
    break;
  case FR_OK:
    file_info->path_exist = true;
    file_info->size = finfo.fsize;
    file_info->date.year = (finfo.fdate >> 9) + 1980;
    file_info->date.month = (finfo.fdate >> 5) & 15;
    file_info->date.month = finfo.fdate & 31;
    file_info->time.hour = (finfo.ftime >> 11);
    file_info->time.minute = (finfo.ftime >> 5) & 63;
    file_info->time.second = finfo.ftime & 31;
    file_info->attrib.readonly = (finfo.fattrib & AM_RDO);
    file_info->attrib.hidden = (finfo.fattrib & AM_HID);
    file_info->attrib.system = (finfo.fattrib & AM_SYS);
    file_info->attrib.archive = (finfo.fattrib & AM_ARC);
    file_info->attrib.directory = (finfo.fattrib & AM_DIR);
    return true;
    break;
  default:
    return false;
    break;
  }

  // should not reach here
  return false;
}

// permission

bool emmc_fs_fix_permission_internal(char *path_buff_internal) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  FILINFO finfo;
  DIR dir;

  // make sure path exists
  if (!emmc_fs_path_exist(path_buff_internal))
    return false;

  // open and walk through
  ExecuteCheck_OKEMMC_SIMPLE(f_opendir(&dir, path_buff_internal));
  int i = strlen(path_buff_internal);
  for (;;) {
    // read next file
    ExecuteCheck_OKEMMC_SIMPLE(f_readdir(&dir, &finfo));

    // if empty, no more files
    if (finfo.fname[0] == 0)
      break;

    // if current dir, skip
    if ((strcmp(finfo.fname, ".") == 0))
      continue;

    // get full path
    sprintf(&path_buff_internal[i], "/%s", finfo.fname);

    // remove all attribute
    ExecuteCheck_OKEMMC_SIMPLE(
        f_chmod(path_buff_internal, 0, AM_RDO | AM_HID | AM_SYS | AM_ARC));

    // if is dir
    if (finfo.fattrib & AM_DIR) {
      // self invoke
      if (!emmc_fs_fix_permission_internal(path_buff_internal))
        return false;
    }

    // reset path
    path_buff_internal[i] = '\0';
  }
  ExecuteCheck_OKEMMC_SIMPLE(f_closedir(&dir));

  // no error, all done
  return true;
}

bool emmc_fs_fix_permission(bool onekey_data, bool user_data) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  bool result = true;
  char path_buff_internal[FF_MAX_LFN];

  if (onekey_data) {
    if (!emmc_wrapper_status.is_mounted_onekey_data)
      return false;
    strcpy(path_buff_internal, "0:");
    result &= emmc_fs_fix_permission_internal(path_buff_internal);
  }
  if (user_data) {
    if (!emmc_wrapper_status.is_mounted_user_data)
      return false;
    strcpy(path_buff_internal, "1:");
    result &= emmc_fs_fix_permission_internal(path_buff_internal);
  }
  return result;
}

// file

bool emmc_fs_file_read(const char *path_buff, uint32_t offset, void *buff,
                       uint32_t target_len, uint32_t *processed_len) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  FIL fhandle;

  // make sure path exists
  if (!emmc_fs_path_exist(path_buff))
    return false;

  // open
  ExecuteCheck_OKEMMC_SIMPLE(f_open(&fhandle, path_buff, FA_READ));
  // seek
  ExecuteCheck_OKEMMC_SIMPLE(f_lseek(&fhandle, offset));
  // read
  ExecuteCheck_OKEMMC_SIMPLE(
      f_read(&fhandle, buff, target_len, (UINT *)processed_len));
  // close
  ExecuteCheck_OKEMMC_SIMPLE(f_close(&fhandle));

  return true;
}

bool emmc_fs_file_write(const char *path_buff, uint32_t offset, void *buff,
                        uint32_t target_len, uint32_t *processed_len,
                        bool overwrite, bool append) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  FIL fhandle;
  BYTE fopenmodes;

  // handle overwrite
  switch (emmc_fs_f_stat(path_buff, NULL)) {
  case FR_OK: // exists
    if (overwrite && append) {
      // can't enable both
      emmc_fs_dbgex_set("file exists, overwrite and append both enabled!");
      return false;
    } else if (overwrite) {
      // overwrite enabled
      ExecuteCheck_OKEMMC_SIMPLE(f_unlink(path_buff)); // remove it
      fopenmodes = FA_CREATE_NEW | FA_WRITE;
      break;
    } else if (append) {
      // append disabled
      fopenmodes = FA_OPEN_EXISTING | FA_WRITE;
      break;
    } else {
      // file exists but non enabled
      emmc_fs_dbgex_set("file exists, overwrite and append both disabled!");
      return false;
    }
  case FR_NO_FILE: // do nothing
    fopenmodes = FA_CREATE_NEW | FA_WRITE;
    break;
  default: // anything else considered as error
    emmc_fs_dbgex_set("emmc_fs_f_stat errored out");
    return false;
    break;
  }

  // open
  ExecuteCheck_OKEMMC_SIMPLE(f_open(&fhandle, path_buff, fopenmodes));

  // for "touch" file, all three params must be set to NULL and zero
  if (!(offset == 0 && buff == NULL && target_len == 0 &&
        processed_len == NULL)) {
    // seek
    ExecuteCheck_OKEMMC_SIMPLE(f_lseek(&fhandle, offset));
    // write
    ExecuteCheck_OKEMMC_SIMPLE(
        f_write(&fhandle, buff, target_len, (UINT *)processed_len));
    // flush (not needed as f_close should flush the buffer)
    // ExecuteCheck_OKEMMC_SIMPLE(f_sync(&fhandle));
  }

  // close
  ExecuteCheck_OKEMMC_SIMPLE(f_close(&fhandle));

  return true;
}

bool emmc_fs_file_touch(const char *path_buff) {
  return emmc_fs_file_write(path_buff, 0, NULL, 0, NULL, false, true);
}

bool emmc_fs_file_delete(const char *path_buff) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  FILINFO finfo;

  if (!emmc_wrapper_status.is_inited)
    return false;

  // check path exist
  switch (emmc_fs_f_stat(path_buff, &finfo)) {
  case FR_OK:                      // exists, remove it
    if (!(finfo.fattrib & AM_DIR)) // make sure it's not a directory
    {
      // remove readonly attribute if exists
      if (finfo.fattrib & AM_RDO) {
        ExecuteCheck_OKEMMC_SIMPLE(f_chmod(path_buff, 0, AM_RDO));
      }

      // remove item
      ExecuteCheck_OKEMMC_SIMPLE(f_unlink(path_buff));

      // return
      return true;
    } else {
      return false;
    }
    break;
  case FR_NO_FILE: // considered as success since we removing it anyways
    return true;
    break;
  default: // anything else considered as error
    return false;
    break;
  }
}

// dir

bool emmc_fs_dir_list_internal(char *path_buff_internal,
                               char *list_subdirs_buff,
                               uint32_t list_subdirs_len, char *list_files_buff,
                               uint32_t list_files_len) {
  emmc_fs_dbgex_clr();

  // status update
  OKEMMC_DBG_STATUS_SETUP();

  FILINFO finfo;
  DIR dir;

  // make sure path exists
  emmc_fs_dbgex_set("check path");
  if (!emmc_fs_path_exist(path_buff_internal))
    return false;
  emmc_fs_dbgex_set("path exits");

  // open and walk through
  ExecuteCheck_OKEMMC_SIMPLE(f_opendir(&dir, path_buff_internal));
  emmc_fs_dbgex_set("opendir");
  int i = strlen(path_buff_internal);
  for (;;) {
    // read next file
    ExecuteCheck_OKEMMC_SIMPLE(f_readdir(&dir, &finfo));

    // if empty, no more files
    if (finfo.fname[0] == 0)
      break;

    // if current dir, skip
    if ((strcmp(finfo.fname, ".") == 0))
      continue;

    // get full path
    if (i == 2)
      sprintf(&path_buff_internal[i], "%s", finfo.fname);
    else
      sprintf(&path_buff_internal[i], "/%s", finfo.fname);

    // if is dir
    if (finfo.fattrib & AM_DIR) {
      // check length
      if ((strlen(list_subdirs_buff) + strlen(path_buff_internal) + 1) >=
          list_subdirs_len) {
        emmc_fs_dbgex_set("list_subdirs_len overflow");
        return false;
      }

      // append to the list
      strcat(list_subdirs_buff, path_buff_internal);
      // use \n as seprater
      strcat(list_subdirs_buff, "\n");
      // self invoke
      if (!emmc_fs_dir_list_internal(path_buff_internal, list_subdirs_buff,
                                     list_subdirs_len, list_files_buff,
                                     list_files_len))
        return false;
    } else {
      // check length
      if ((strlen(list_files_buff) + strlen(path_buff_internal) + 1) >=
          list_files_len) {
        emmc_fs_dbgex_set("list_files_len overflow");
        return false;
      }

      // append to the list
      strcat(list_files_buff, path_buff_internal);
      // use \n as seprater
      strcat(list_files_buff, "\n");
    }

    // reset path
    path_buff_internal[i] = '\0';
  }
  ExecuteCheck_OKEMMC_SIMPLE(f_closedir(&dir));

  // no error, all done
  emmc_fs_dbgex_set("done");
  return true;
}

bool emmc_fs_dir_list(const char *path_buff, char *list_subdirs_buff,
                      uint32_t list_subdirs_len, char *list_files_buff,
                      uint32_t list_files_len) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  // copy path to non-const buffer
  char path_buff_internal[FF_MAX_LFN];
  strncpy(path_buff_internal, path_buff, FF_MAX_LFN);

  // clear buffers
  memset(list_subdirs_buff, '\0', list_subdirs_len);
  memset(list_files_buff, '\0', list_files_len);

  return emmc_fs_dir_list_internal(path_buff_internal, list_subdirs_buff,
                                   list_subdirs_len, list_files_buff,
                                   list_files_len);
}

bool emmc_fs_dir_create_internal(char *path_buff_internal) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  FILINFO finfo;

  // check path exist
  switch (emmc_fs_f_stat(path_buff_internal, &finfo)) {
  case FR_OK:
    // if path exists and is a directory, considered as success since we
    // creating it anyways
    if (finfo.fattrib & AM_DIR)
      return true;
    // if path exixts but is not a directory, considered as error
    else
      return false;
    break;
  case FR_NO_FILE: // if path not exists, create it
    ExecuteCheck_OKEMMC_SIMPLE(f_mkdir(path_buff_internal));
    break;
  default: // anything else considered as error
    return false;
    break;
  }

  // no error, all done
  return true;
}

bool emmc_fs_dir_make(const char *path_buff) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  // vars
  char *token;

  char path_buff_creating[FF_MAX_LFN];
  memset(path_buff_creating, '\0', FF_MAX_LFN);

  char path_buff_reamining[FF_MAX_LFN];
  strncpy(path_buff_reamining, path_buff, FF_MAX_LFN);

  // create it recursively
  while (true) {
    // get next chunk
    if (strlen(path_buff_creating) == 0)
      // first time call
      token = strtok(path_buff_reamining, "/");
    else
      // following call
      token = strtok(NULL, "/");

    // no more chunk, break
    if (token == NULL)
      break;

    // append chunk to buffer
    strncat(path_buff_creating, token, FF_MAX_LFN - strlen(path_buff_creating));

    // create path
    if (!emmc_fs_dir_create_internal(path_buff_creating))
      return false;

    // append path seprator, this has to be after the call to f_mkdir
    // since f_mkdir won't accept path like "0:target_dir/"
    strcat(path_buff_creating, "/");
  }

  // test and make sure target path created
  FILINFO finfo;
  ExecuteCheck_OKEMMC_SIMPLE(emmc_fs_f_stat(path_buff, &finfo));
  if (finfo.fattrib & AM_DIR)
    return true;
  else
    return false;
}

bool emmc_fs_dir_delete_internal(char *path_buff_internal) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  FILINFO finfo;
  DIR dir;

  // check path exist
  switch (emmc_fs_f_stat(path_buff_internal, &finfo)) {
  case FR_OK:                   // do nothing
    if (finfo.fattrib & AM_DIR) // make sure it's a directory to begin with
    {
      break;
    } else {
      return false;
    }
  case FR_NO_FILE: // considered as success since we removing it anyways
    return true;
    break;
  default: // anything else considered as error
    return false;
    break;
  }

  // open and walk through
  ExecuteCheck_OKEMMC_SIMPLE(f_opendir(&dir, path_buff_internal));
  int i = strlen(path_buff_internal);
  for (;;) {
    // read next file
    ExecuteCheck_OKEMMC_SIMPLE(f_readdir(&dir, &finfo));

    // if empty, no more files
    if (finfo.fname[0] == 0)
      break;

    // if current dir, skip
    if ((strcmp(finfo.fname, ".") == 0))
      continue;

    // get full path
    sprintf(&path_buff_internal[i], "/%s", finfo.fname);

    // remove readonly attribute
    ExecuteCheck_OKEMMC_SIMPLE(f_chmod(path_buff_internal, 0, AM_RDO));

    // if is dir
    if (finfo.fattrib & AM_DIR) {
      // self invoke
      if (!emmc_fs_dir_delete_internal(path_buff_internal))
        return false;
    }
    // if is file
    else {
      // delete directly
      ExecuteCheck_OKEMMC_SIMPLE(f_unlink(path_buff_internal));
    }

    // reset path
    path_buff_internal[i] = '\0';
  }
  ExecuteCheck_OKEMMC_SIMPLE(f_closedir(&dir));

  // delete dir
  ExecuteCheck_OKEMMC_SIMPLE(f_unlink(path_buff_internal));

  // no error, all done
  return true;
}

bool emmc_fs_dir_delete(const char *path_buff) {
  // status update
  OKEMMC_DBG_STATUS_SETUP();

  if (!emmc_wrapper_status.is_inited)
    return false;

  // copy path to non-const buffer
  char path_buff_internal[FF_MAX_LFN];
  strncpy(path_buff_internal, path_buff, FF_MAX_LFN);

  return emmc_fs_dir_delete_internal(path_buff_internal);
}
