/**@file printf_ext.h
 * @brief Extensions to printf and frieds
 * 
 * @author Tiago Alves Macambira
 * @version $Id: printf_ext.h,v 1.1 2004-02-12 15:48:24 tmacam Exp $
 * 
 */
/**@brief Initiates all the printf extensions
 *
 * The known extensions are:
 *  - %H to print a e2k_hash*
 *  - %T to print current Date/Time
 *  - %A to print a struct tuple4*
 *
 * @return 0 in case of success. -1 otherwise
 */
int setup_printf_extenstions();
