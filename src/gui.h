/*
 *  gui.h: An ncurses GUI for kwipe.
 *
 *  Copyright Darik Horn <dajhorn-dban@vanadac.com>.
 *
 *  Modifications to original dwipe Copyright Andy Beverley <andy@andybev.com>
 *
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation, version 2.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef GUI_H_
#define GUI_H_

void kwipe_gui_free( void );  // Stop the GUI.
void kwipe_gui_init( void );  // Start the GUI.
void kwipe_gui_create_main_window( void );  // Create the main window
void kwipe_gui_create_header_window( void );  // Create the header window
void kwipe_gui_create_footer_window( const char* );  // Create the footer window and write text
void kwipe_gui_create_options_window( void );  // Create the options window
void kwipe_gui_create_stats_window( void );  // Create the stats window
void kwipe_gui_create_all_windows_on_terminal_resize(
    int force_creation,
    const char* footer_text );  // If terminal is resized recreate all windows

/**
 * The primary user interface.  Allows the user to
 * change options and specify the devices to be wiped.
 *
 * @parameter  count       The number of contexts in the array.
 * @parameter  c           An array of device contexts.
 *
 * @modifies   c[].select  Sets the select flag according to user input.
 * @modifies   options     Sets program options according to to user input.
 *
 */
void kwipe_gui_select( int count, kwipe_context_t** c );  // Select devices to wipe.
void* kwipe_gui_status( void* ptr );  // Update operation progress.
void kwipe_gui_method( void );  // Change the method option.
void kwipe_gui_options( void );  // Update the options window.
void kwipe_gui_prng( void );  // Change the prng option.
void kwipe_gui_rounds( void );  // Change the rounds option.
void kwipe_gui_verify( void );  // Change the verify option.
void kwipe_gui_noblank( void );  // Change the noblank option.
void kwipe_gui_config( void );  // Change the kwipe settings
void kwipe_gui_edit_organisation( void );  // Edit organisation performing the erasure
void kwipe_gui_organisation_business_name( const char* );  // Edit business name performing erase
void kwipe_gui_organisation_business_address( const char* );  // Edit business address performing erase
void kwipe_gui_organisation_contact_name( const char* );  // Edit business contact name
void kwipe_gui_organisation_contact_phone( const char* );  // Edit business contact phone
void kwipe_gui_organisation_op_tech_name( const char* );  // Edit the name of the operator/technician
void kwipe_gui_list( int, char* window_title, char**, int* );
void kwipe_gui_add_customer( void );  // Add new customer
void kwipe_gui_add_customer_name( char* );  // Add new customer name
void kwipe_gui_add_customer_address( char* );  // Add new customer address
void kwipe_gui_add_customer_contact_name( char* );  // Add new customer contact name
void kwipe_gui_add_customer_contact_phone( char* );  // Add new customer contact phone
int kwipe_gui_yes_no_footer( void );  // Change footer to yes no

/** kwipe_gui_preview_org_customer( int )
 * Display a editable preview of organisation, customer and date/time
 *
 * @param int mode 0 = use prior to drive selection
 *                 1 = use in config menus
 * The different modes simply change the text in the footer menu and in the case
 * of mode 0 enable the A key which means accept & display drive selection.
 */
void kwipe_gui_preview_org_customer( int );  // Preview window  for wipe organisation and customer

void kwipe_gui_set_system_year( void );  // Set the systems current year
void kwipe_gui_set_system_month( void );  // Set the systems month
void kwipe_gui_set_system_day( void );  // Set the system day of the month
void kwipe_gui_set_system_hour( void );  // Set the system hour
void kwipe_gui_set_system_minute( void );  // Set the system minute

/**
 * Truncate a string based on start position and terminal width
 *
 * @parameter wcols         Width of window, obtained from getmaxyx(..)
 * @parameter start_column  Start column where the string starts
 * @parameter input_string  The string to be truncated if necessary
 * @parameter ouput_string  The possibly truncated string
 * @parameter ouput_string_length   Max length of output string
 * @Return returns a pointer to the output string
 */
char* str_truncate( int, int, const char*, char*, int );  // Truncate string based on start column and terminal width

/**
 * Set system date and time
 *
 *  @parameter void
 *  @Return void
 */
void kwipe_gui_set_date_time( void );

int spinner( kwipe_context_t** ptr, int );  // Return the next spinner character
void temp1_flash( kwipe_context_t* );  // toggles term1_flash_status, which flashes the temperature

/**
 * If the current drive temperature is available, print it to the GUI.
 * This function determines if the drive temperature limits are specified &
 * if so, whether the temperature should be printed as white text on blue if the
 * drive is operating within it's temperature specification or red text on
 * blue if the drive has exceeded the critical high temperature or black on
 * blue if the drive has dropped below the drives minimum temperature specification.
 * @param pointer to the drive context
 */
void wprintw_temperature( kwipe_context_t* );

int compute_stats( void* ptr );
void kwipe_update_speedring( kwipe_speedring_t* speedring, u64 speedring_done, time_t speedring_now );

#define NOMENCLATURE_RESULT_STR_SIZE 8

/* Note Do not change unless you understand how this value affects keyboard response and screen refresh when
 * the drive selection screen is displayed. (prior to wipe starting). */
#define GETCH_BLOCK_MS 250 /* millisecond block time for getch() */

/* Note The value of 1 (100ms) is the ideal speed for screen refresh during a wipe, a value of 2 is noticeably slower,
 * don't change unless you understand how this value affects keyboard responsiveness and speed of screen stats/spinner
 * updating */
#define GETCH_GUI_STATS_UPDATE_MS 1 /* 1 * 100 = 1/10/sec = millisecond block time for gui stats screen updates */

#define FIELD_LENGTH 256

#define MAX_TITLE_LENGTH 76

#define YES 1
#define NO 0

#define SHOWING_PRIOR_TO_DRIVE_SELECTION 0
#define SHOWING_IN_CONFIG_MENUS 1

#endif /* GUI_H_ */
